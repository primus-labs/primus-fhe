//! PIOP for transformation from Zq to R/QR
//! The prover wants to convince that a \in Zq is correctly transformed into c \in R/QR := ZQ^n s.t.
//! if a' = 2n/q * a < n, c has only one nonzero element 1 at index a'
//! if a' = 2n/q * a >= n, c has only one nonzero element -1 at index a' - n
//! q: the modulus for a
//! Q: the modulus for elements of vector c
//! n: the length of vector c
//!
//! Given M instances of transformation from Zq to R/QR, the main idea of this IOP is to prove:
//! For x \in \{0, 1\}^l
//!
//! 1. (2n/q) * a(x) = k(x) * n + r(x) => reduced to the evaluation of a random point since the LHS and RHS are both MLE
//!
//! 2. r(x) \in [q] => the range check can be proved by the Bit Decomposition IOP
//!
//! 3. k(x) \cdot (1 - k(x)) = 0  => can be reduced to prove the sum
//!     $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [k(x) \cdot (1 - k(x))] = 0$
//!     where u is the common random challenge from the verifier, used to instantiate the sum
//!
//! 4. (r(x) + 1)(1 - 2k(x)) = s(x) => can be reduced to prove the sum
//!     $\sum_{x\in \{0,1\}^{\log M}} eq(u,x) \cdot ((r(x) + 1)(1 - 2k(x)) - s(x)) = 0$
//!     where u is the common random challenge from the verifier, used to instantiate the sum
//!
//! 5. \sum_{y \in {0,1}^logN} c(u,y)t(y) = s(u) => can be reduced to prove the sum
//!    \sum_{y \in {0,1}^logN} c_u(y)t(y) = s(u)
//!     where u is the common random challenge from the verifier, used to instantiate the sum
//!     and c'(y) is computed from c_u(y) = c(u,y)

use std::marker::PhantomData;
use std::rc::Rc;

use super::bit_decomposition::{
    BitDecompositionProof, BitDecompositionSubClaim, DecomposedBits, DecomposedBitsInfo,
};
use crate::piop::BitDecomposition;
use crate::sumcheck::prover::ProverMsg;
use crate::utils::eval_identity_function;

use crate::sumcheck::MLSumcheck;
use crate::utils::gen_identity_evaluations;
use algebra::{
    AsFrom, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension,
    PolynomialInfo, SparsePolynomial,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// proof generated by prover
pub struct TransformZqtoRQProof<F: Field> {
    /// singe rangecheck proof for r
    pub rangecheck_msg: BitDecompositionProof<F>,
    /// sumcheck proofs for
    /// \sum_{x} eq(u,x) * k(x) * (1 - k(x)) = 0;
    /// \sum_{x} eq(u,x) * ((r(x) + 1) * (1 - 2k(x)) - s(x)) = 0;
    /// \sum_{y} c_u(y) * t(y) = s(u)
    pub sumcheck_msgs: Vec<Vec<ProverMsg<F>>>,
    /// the claimed sum of the third sumcheck i.e. s(u)
    pub s_u: F,
}

/// subclaim returned to verifier
pub struct TransformZqtoRQSubclaim<F: Field> {
    /// rangecheck subclaim for a, b, c \in Zq
    pub(crate) rangecheck_subclaim: BitDecompositionSubClaim<F>,
    /// subcliam
    pub sumcheck_points: Vec<Vec<F>>,
    /// expected value returned in the last round of the sumcheck
    pub sumcheck_expected_evaluations: Vec<F>,
}

/// Stores the parameters used for transformation from Zq to RQ and the inputs and witness for prover.
/// example parameters: LWE: n=512, q=512, RLWE: N=1024, Q=132120577
pub struct TransformZqtoRQInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// modulus of Zq
    pub q: usize,
    /// modulus of RQ
    pub capital_q: usize,
    /// row_num of c
    pub m: usize,
    /// column_num of c
    pub n: usize,
    /// inputs c
    pub c: Vec<Rc<SparsePolynomial<F>>>,
    /// inputs a
    pub a: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness k
    pub k: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness r
    pub r: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness s
    pub s: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness to check the range of a, b, c
    pub r_bits: DecomposedBits<F>,
}

/// Stores the parameters used for addition in Zq and the public info for verifier.
pub struct TransformZqtoRQInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// modulus of Zq
    pub q: usize,
    /// modulus of RQ
    pub capital_q: usize,
    /// row_num of c
    pub m: usize,
    /// column_num of c
    pub n: usize,
    /// decomposition info for range check (i.e. bit decomposition)
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
}

impl<F: Field> TransformZqtoRQInstance<F> {
    /// Extract the information of addition in Zq for verification
    #[inline]
    pub fn info(&self) -> TransformZqtoRQInstanceInfo<F> {
        TransformZqtoRQInstanceInfo {
            num_vars: self.num_vars,
            q: self.q,
            capital_q: self.capital_q,
            m: self.m,
            n: self.n,
            decomposed_bits_info: self.r_bits.info(),
        }
    }

    /// Construct a new instance from vector
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        q: usize,
        capital_q: usize,
        c: Vec<Rc<SparsePolynomial<F>>>,
        a: Rc<DenseMultilinearExtension<F>>,
        k: &Rc<DenseMultilinearExtension<F>>,
        r: &Rc<DenseMultilinearExtension<F>>,
        s: &Rc<DenseMultilinearExtension<F>>,
        base: F,
        base_len: u32,
        bits_len: u32,
    ) -> Self {
        let num_vars = a.num_vars;
        let c_num_vars = c[0].num_vars;
        let n = 2_usize.pow(c_num_vars as u32);
        let m = c.len();

        assert_eq!(k.num_vars, num_vars);
        assert_eq!(r.num_vars, num_vars);
        assert_eq!(s.num_vars, num_vars);
        assert_eq!(2_usize.pow(num_vars as u32), m);
        assert_eq!(2 * n % q, 0);
        c.iter().for_each(|x| {
            assert_eq!(x.num_vars, c_num_vars);
            assert_eq!(x.evaluations.len(), 1);
        });

        // Rangecheck is defaultly designed for batching version, so we should construct a vector of one element r_bits
        let r_bits = vec![r.get_decomposed_mles(base_len, bits_len)];

        Self {
            q,
            capital_q,
            m,
            n,
            num_vars,
            c,
            a,
            k: Rc::clone(k),
            r: Rc::clone(r),
            s: Rc::clone(s),
            r_bits: DecomposedBits {
                base,
                base_len,
                bits_len,
                num_vars,
                instances: r_bits,
            },
        }
    }
}

/// SNARKs for transformation from Zq to RQ i.e. R/QR
pub struct TransformZqtoRQ<F: Field>(PhantomData<F>);

impl<F: Field> TransformZqtoRQ<F> {
    /// Prove transformation from a \in Zq to c \in R/QR
    pub fn prove(
        transform_instance: &TransformZqtoRQInstance<F>,
        u: &[F],
    ) -> TransformZqtoRQProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, transform_instance, u)
    }

    /// Prove transformation from Zq to R/QR given input a, c, witness k, r, s and the decomposed bits for r.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        transform_instance: &TransformZqtoRQInstance<F>,
        u: &[F],
    ) -> TransformZqtoRQProof<F> {
        let dim = u.len();
        assert_eq!(dim, transform_instance.num_vars);

        // 1. rangecheck for r
        let rangecheck_msg =
            BitDecomposition::prove_as_subprotocol(fs_rng, &transform_instance.r_bits, u);

        // 2. execute sumcheck for \sum_{x \in {0,1}^logM} eq(u, x) * k(x) * (1-k(x)) = 0 i.e. k(x) \in \{0,1\}^dim
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(dim);

        let mut product = Vec::with_capacity(3);
        let mut op_coefficient = Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u)));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&transform_instance.k));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&transform_instance.k));
        op_coefficient.push((-F::ONE, F::ONE));
        poly.add_product_with_linear_op(product, &op_coefficient, F::ONE);

        let first_sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for transformation from Zq to RQ failed");

        // 3. execute sumcheck for \sum_{x \in {0,1}^logM} eq(u,x)((r(x) + 1) * (1 - 2k(x)) - s(x)) = 0 i.e. (r(x) + 1)(1 - 2k(x)) = s(x) for x in \{0,1\}^dim
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(dim);

        let mut product = Vec::with_capacity(3);
        let mut op_coefficient = Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u)));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&transform_instance.r));
        op_coefficient.push((F::ONE, F::ONE));
        product.push(Rc::clone(&transform_instance.k));
        op_coefficient.push((-(F::ONE + F::ONE), F::ONE));
        poly.add_product_with_linear_op(product, &op_coefficient, F::ONE);

        let mut product = Vec::with_capacity(2);
        let mut op_coefficient = Vec::with_capacity(2);
        product.push(Rc::new(gen_identity_evaluations(u)));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&transform_instance.s));
        op_coefficient.push((-F::ONE, F::ZERO));
        poly.add_product_with_linear_op(product, &op_coefficient, F::ONE);

        let second_sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for transformation from Zq to RQ failed");

        // 4. sumcheck for \sum_{y \in {0,1}^logN} c(u,y)t(y) = s(u)
        let c_num_vars = transform_instance.n.ilog(2) as usize;

        // construct c_u
        let eq_u = gen_identity_evaluations(u).evaluations;
        let mut c_u_evaluations = vec![F::ZERO; transform_instance.n];
        transform_instance
            .c
            .iter()
            .enumerate()
            .for_each(|(x_idx, sparse_p)| {
                sparse_p.iter().for_each(|(y_idx, value)| {
                    c_u_evaluations[*y_idx] += eq_u[x_idx] * value;
                });
            });
        let c_u = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            c_num_vars,
            c_u_evaluations,
        ));

        // construct t
        let t_evaluations = (1..=transform_instance.n)
            .map(|i| F::new(F::Value::as_from(i as u32)))
            .collect();
        let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            c_num_vars,
            t_evaluations,
        ));

        let mut poly = <ListOfProductsOfPolynomials<F>>::new(c_num_vars);
        let mut product = Vec::with_capacity(2);
        let mut op_coefficient = Vec::with_capacity(2);
        product.push(Rc::clone(&c_u));
        op_coefficient.push((F::ONE, F::ZERO));
        product.push(Rc::clone(&t));
        op_coefficient.push((F::ONE, F::ZERO));
        poly.add_product_with_linear_op(product, &op_coefficient, F::ONE);

        let third_sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for transformation from Zq to RQ failed");

        TransformZqtoRQProof {
            rangecheck_msg,
            sumcheck_msgs: vec![
                first_sumcheck_proof.0,
                second_sumcheck_proof.0,
                third_sumcheck_proof.0,
            ],
            s_u: transform_instance.s.evaluate(u),
        }
    }

    /// Verify transformation from Zq to RQ given the proof and the verification key for bit decomposistion
    pub fn verify(
        proof: &TransformZqtoRQProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
        c_num_vars: usize,
    ) -> TransformZqtoRQSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verifier_as_subprotocol(&mut fs_rng, proof, decomposed_bits_info, c_num_vars)
    }

    /// Verify transformation from Zq to RQ given the proof and the verification key for bit decomposistion
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &TransformZqtoRQProof<F>,
        decomposed_bits_info: &DecomposedBitsInfo<F>,
        c_num_vars: usize,
    ) -> TransformZqtoRQSubclaim<F> {
        //TODO sample randomness via Fiat-Shamir RNG

        // 1. rangecheck
        let rangecheck_subclaim = BitDecomposition::verifier_as_subprotocol(
            fs_rng,
            &proof.rangecheck_msg,
            decomposed_bits_info,
        );

        // 2. sumcheck
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: decomposed_bits_info.num_vars,
        };

        let first_subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::ZERO, &proof.sumcheck_msgs[0])
                .expect("sumcheck protocol for transformation from Zq to RQ failed");

        let second_subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::ZERO, &proof.sumcheck_msgs[1])
                .expect("sumcheck protocol for transformation from Zq to RQ failed");

        let poly_info = PolynomialInfo {
            max_multiplicands: 2,
            num_variables: c_num_vars,
        };
        let third_subclaim = MLSumcheck::verify_as_subprotocol(
            fs_rng,
            &poly_info,
            proof.s_u,
            &proof.sumcheck_msgs[2],
        )
        .expect("sumcheck protocol for transformation from Zq to RQ failed");

        TransformZqtoRQSubclaim {
            rangecheck_subclaim,
            sumcheck_points: vec![
                first_subclaim.point,
                second_subclaim.point,
                third_subclaim.point,
            ],
            sumcheck_expected_evaluations: vec![
                first_subclaim.expected_evaluations,
                second_subclaim.expected_evaluations,
                third_subclaim.expected_evaluations,
            ],
        }
    }
}

impl<F: Field> TransformZqtoRQSubclaim<F> {
    /// verify the sumcliam
    /// * a stores the input and c stores the output of transformation from Zq to RQ
    /// * k, r, s stores the introduced witness
    /// * r_bits stores the decomposed bits for r
    /// * u is the common random challenge from the verifier, used to instantiate the sumcheck.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim(
        &self,
        q: usize,
        a: Rc<DenseMultilinearExtension<F>>,
        c_dense: &DenseMultilinearExtension<F>,
        k: &DenseMultilinearExtension<F>,
        r: &[Rc<DenseMultilinearExtension<F>>],
        s: &DenseMultilinearExtension<F>,
        r_bits: &[Vec<Rc<DenseMultilinearExtension<F>>>],
        u: &[F],
        info: &TransformZqtoRQInstanceInfo<F>,
    ) -> bool {
        assert_eq!(r_bits.len(), 1);
        assert_eq!(r.len(), 1);

        // check 1: subclaim for rangecheck, r \in [Zq]
        if !self
            .rangecheck_subclaim
            .verify_subclaim(r, r_bits, u, &info.decomposed_bits_info)
        {
            return false;
        }

        // check 2: subclaim for sumcheck, i.e. eq(u, point) * k(point) * (1 - k(point)) = 0
        let eval_k = k.evaluate(&self.sumcheck_points[0]);
        if eval_identity_function(u, &self.sumcheck_points[0]) * eval_k * (F::ONE - eval_k)
            != self.sumcheck_expected_evaluations[0]
        {
            return false;
        }

        // check 3: subclaim for sumcheck, i.e. eq(u, point) * ((r(point) + 1) * (1 - 2 * k(point)) - s(point)) = 0
        if eval_identity_function(u, &self.sumcheck_points[1])
            * ((r[0].evaluate(&self.sumcheck_points[1]) + F::ONE)
                * (F::ONE - (F::ONE + F::ONE) * k.evaluate(&self.sumcheck_points[1]))
                - s.evaluate(&self.sumcheck_points[1]))
            != self.sumcheck_expected_evaluations[1]
        {
            return false;
        }

        // check 4: subclaim for sumcheck, i.e. c(u, point) * t(point) = s(u)
        let eval_c_u = c_dense.evaluate(&[&self.sumcheck_points[2], u].concat());
        let t_evaluations = (1..=info.n)
            .map(|i| F::new(F::Value::as_from(i as u32)))
            .collect();
        let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            info.n.ilog(2) as usize,
            t_evaluations,
        ));
        if eval_c_u * t.evaluate(&self.sumcheck_points[2]) != self.sumcheck_expected_evaluations[2]
        {
            return false;
        }

        // check 5: (2n/q) * a(u) = k(u) * n + r(u)
        let n = F::new(F::Value::as_from(info.n as u32));
        let q = F::new(F::Value::as_from(q as u32));

        (F::ONE + F::ONE) * (n / q) * a.evaluate(u) == n * k.evaluate(u) + r[0].evaluate(u)
    }

    /// verify the sumcliam
    /// * a stores the input and c stores the output of transformation from Zq to RQ
    /// * k, r, s stores the introduced witness
    /// * r_bits stores the decomposed bits for r
    /// * u is the common random challenge from the verifier, used to instantiate the sumcheck.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim_without_oracle(
        &self,
        q: usize,
        a: Rc<DenseMultilinearExtension<F>>,
        c_sparse: &[Rc<SparsePolynomial<F>>],
        k: &DenseMultilinearExtension<F>,
        r: &[Rc<DenseMultilinearExtension<F>>],
        s: &DenseMultilinearExtension<F>,
        r_bits: &[Vec<Rc<DenseMultilinearExtension<F>>>],
        u: &[F],
        info: &TransformZqtoRQInstanceInfo<F>,
    ) -> bool {
        assert_eq!(r_bits.len(), 1);
        assert_eq!(r.len(), 1);

        // check 1: subclaim for rangecheck, r \in [Zq]
        if !self
            .rangecheck_subclaim
            .verify_subclaim(r, r_bits, u, &info.decomposed_bits_info)
        {
            return false;
        }

        // check 2: subclaim for sumcheck, i.e. eq(u, point) * k(point) * (1 - k(point)) = 0
        let eval_k = k.evaluate(&self.sumcheck_points[0]);
        if eval_identity_function(u, &self.sumcheck_points[0]) * eval_k * (F::ONE - eval_k)
            != self.sumcheck_expected_evaluations[0]
        {
            return false;
        }

        // check 3: subclaim for sumcheck, i.e. eq(u, point) * ((r(point) + 1) * (1 - 2 * k(point)) - s(point)) = 0
        if eval_identity_function(u, &self.sumcheck_points[1])
            * ((r[0].evaluate(&self.sumcheck_points[1]) + F::ONE)
                * (F::ONE - (F::ONE + F::ONE) * k.evaluate(&self.sumcheck_points[1]))
                - s.evaluate(&self.sumcheck_points[1]))
            != self.sumcheck_expected_evaluations[1]
        {
            return false;
        }

        // check 4: subclaim for sumcheck, i.e. c(u, point) * t(point) = s(u)
        let eq_u = gen_identity_evaluations(u);
        let eq_v = gen_identity_evaluations(&self.sumcheck_points[2]);
        let mut eval_c_u = F::ZERO;
        c_sparse.iter().enumerate().for_each(|(x_idx, c)| {
            assert_eq!(c.evaluations.len(), 1);
            let (y_idx, c_val) = c.evaluations[0];
            eval_c_u += eq_u[x_idx] * eq_v[y_idx] * c_val;
        });

        let t_evaluations = (1..=info.n)
            .map(|i| F::new(F::Value::as_from(i as u32)))
            .collect();
        let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            info.n.ilog(2) as usize,
            t_evaluations,
        ));
        if eval_c_u * t.evaluate(&self.sumcheck_points[2]) != self.sumcheck_expected_evaluations[2]
        {
            return false;
        }

        // check 5: (2n/q) * a(u) = k(u) * n + r(u)
        let n = F::new(F::Value::as_from(info.n as u32));
        let q = F::new(F::Value::as_from(q as u32));

        (F::ONE + F::ONE) * (n / q) * a.evaluate(u) == n * k.evaluate(u) + r[0].evaluate(u)
    }
}

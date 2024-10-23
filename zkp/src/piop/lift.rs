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
//! 2. r(x) \in [N] => the range check can be proved by the Bit Decomposition IOP
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
use super::{
    BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo,
};
use crate::sumcheck::{self, verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, gen_sparse_at_u, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo, SparsePolynomial,
};
use bincode::Result;
use core::fmt;
use itertools::izip;
use pcs::PolynomialCommitmentScheme;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

/// Instance of lifting Zq to RQ.
/// In this instance, we require the outputs.len() == 1 << num_vars
pub struct LiftInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// modulus of Zq
    pub q: F,
    /// dimension of RWLE denoted by N
    pub dim_rlwe: F,
    /// input a in Zq
    pub input: Rc<DenseMultilinearExtension<F>>,
    /// output C = (c_0, ..., c_{N-1})^T \in F^{N * N}
    pub outputs: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// sparse representation of outputs
    pub sparse_outputs: Vec<Rc<SparsePolynomial<F>>>,
    /// the relation (2N/q) * a = k * N + r
    /// introduced witness k
    pub k: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness reminder r
    pub reminder: Rc<DenseMultilinearExtension<F>>,
    /// decomposed bits of introduced reminder
    pub reminder_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// introduced witness prod denoted by s(x) = (r(x) + 1) * (1 - 2k(x))
    pub prod: Rc<DenseMultilinearExtension<F>>,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

/// Information of LiftInstance
#[derive(Serialize, Deserialize)]
pub struct LiftInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// number of instances.
    pub num_instances: usize,
    /// modulus of Zq
    pub q: F,
    /// dimension of RWLE denoted by N
    pub dim_rlwe: F,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for LiftInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "An instance of Transformation from Zq to RQ: #vars = {}",
            self.num_vars,
        )?;
        write!(f, "- containing ")?;
        self.bits_info.fmt(f)
    }
}

impl<F: Field> LiftInstanceInfo<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + self.num_instances + self.bits_info.bits_len
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Generate the number of variables in the committed polynomial.
    #[inline]
    pub fn generate_num_var(&self) -> usize {
        self.num_vars + self.log_num_oracles()
    }

    /// Construct an EF version.
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> LiftInstanceInfo<EF> {
        LiftInstanceInfo::<EF> {
            num_vars: self.num_vars,
            num_instances: self.num_instances,
            q: EF::from_base(self.q),
            dim_rlwe: EF::from_base(self.dim_rlwe),
            bits_info: self.bits_info.to_ef(),
        }
    }

    /// Generate table [1,...N].
    pub fn generate_table(&self) -> Rc<DenseMultilinearExtension<F>> {
        let mut acc = F::zero();
        let mut table = vec![F::zero(); 1 << self.num_vars];
        for t in table.iter_mut() {
            acc += F::one();
            *t = acc;
        }

        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            self.num_vars,
            table,
        ))
    }
}

impl<F: Field> LiftInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> LiftInstanceInfo<F> {
        LiftInstanceInfo {
            num_vars: self.num_vars,
            num_instances: self.outputs.len(),
            q: self.q,
            dim_rlwe: self.dim_rlwe,
            bits_info: self.bits_info.clone(),
        }
    }

    /// Pack all the involved small polynomials into a single vector
    pub fn pack_all_mles(&self) -> Vec<F> {
        self.input
            .iter()
            .chain(self.outputs.iter().flat_map(|output| output.iter()))
            .chain(self.k.iter())
            .chain(self.reminder.iter())
            .chain(self.reminder_bits.iter().flat_map(|bit| bit.iter()))
            .chain(self.prod.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let info = self.info();
        let num_vars = info.generate_num_var();
        let num_zeros_padded = (1 << num_vars) - info.num_oracles() * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> LiftInstance<EF> {
        LiftInstance::<EF> {
            num_vars: self.num_vars,
            q: EF::from_base(self.q),
            dim_rlwe: EF::from_base(self.dim_rlwe),
            input: Rc::new(self.input.to_ef::<EF>()),
            outputs: self
                .outputs
                .iter()
                .map(|output| Rc::new(output.to_ef::<EF>()))
                .collect(),
            sparse_outputs: self
                .sparse_outputs
                .iter()
                .map(|output| Rc::new(output.to_ef::<EF>()))
                .collect(),
            k: Rc::new(self.k.to_ef::<EF>()),
            reminder: Rc::new(self.reminder.to_ef::<EF>()),
            reminder_bits: self
                .reminder_bits
                .iter()
                .map(|bit| Rc::new(bit.to_ef::<EF>()))
                .collect(),
            prod: Rc::new(self.prod.to_ef::<EF>()),
            bits_info: self.bits_info.to_ef::<EF>(),
        }
    }

    /// Evaluate at the same random point
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> LiftInstanceEval<F> {
        LiftInstanceEval {
            input: self.input.evaluate(point),
            outputs: self
                .outputs
                .iter()
                .map(|output| output.evaluate(point))
                .collect(),
            k: self.k.evaluate(point),
            reminder: self.reminder.evaluate(point),
            reminder_bits: self
                .reminder_bits
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
            prod: self.prod.evaluate(point),
        }
    }

    /// Evaluate at the same random point
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> LiftInstanceEval<EF> {
        LiftInstanceEval {
            input: self.input.evaluate_ext(point),
            outputs: self
                .outputs
                .iter()
                .map(|output| output.evaluate_ext(point))
                .collect(),
            k: self.k.evaluate_ext(point),
            reminder: self.reminder.evaluate_ext(point),
            reminder_bits: self
                .reminder_bits
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
            prod: self.prod.evaluate_ext(point),
        }
    }

    /// Extract DecomposedBits instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionInstance<F> {
        BitDecompositionInstance {
            base: self.bits_info.base,
            base_len: self.bits_info.base_len,
            bits_len: self.bits_info.bits_len,
            num_vars: self.num_vars,
            d_val: vec![Rc::clone(&self.reminder)],
            d_bits: self.reminder_bits.to_owned(),
        }
    }
}

impl<F: DecomposableField> LiftInstance<F> {
    /// Construct an instance
    #[inline]
    pub fn new(
        num_vars: usize,
        q: F,
        dim_rlwe: F,
        input: &Rc<DenseMultilinearExtension<F>>,
        outputs: &[Rc<DenseMultilinearExtension<F>>],
        sparse_outputs: &[Rc<SparsePolynomial<F>>],
        bits_info: &BitDecompositionInstanceInfo<F>,
    ) -> Self {
        assert_eq!(outputs.len(), 1 << num_vars);
        // factor = 2N/q
        let f_two = F::one() + F::one();
        let factor = f_two * dim_rlwe / q;
        let mapped_input = input.iter().map(|x| *x * factor).collect::<Vec<_>>();
        let mut k = vec![F::zero(); 1 << num_vars];
        let mut reminder = vec![F::zero(); 1 << num_vars];
        // (2N/q) * input = k * N + r
        for (m_in, k_, r) in izip!(mapped_input.iter(), k.iter_mut(), reminder.iter_mut()) {
            (*k_, *r) = match m_in < &dim_rlwe {
                true => (F::zero(), *m_in),
                false => (F::one(), *m_in - dim_rlwe),
            };
        }

        let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, k));
        let reminder = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars, reminder,
        ));
        let reminder_bits = reminder.get_decomposed_mles(bits_info.base_len, bits_info.bits_len);
        let bits_info = BitDecompositionInstanceInfo {
            base: bits_info.base,
            base_len: bits_info.base_len,
            bits_len: bits_info.bits_len,
            num_vars,
            num_instances: 1,
        };

        // s = (r + 1) * (1 - 2k)
        let prod = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            reminder
                .iter()
                .zip(k.iter())
                .map(|(r, _k)| (*r + F::one()) * (F::one() - f_two * *_k))
                .collect::<Vec<F>>(),
        ));

        let mut acc = F::zero();
        let mut table = vec![F::zero(); 1 << num_vars];
        for t in table.iter_mut() {
            acc += F::one();
            *t = acc;
        }
        LiftInstance {
            num_vars,
            q,
            dim_rlwe,
            input: input.to_owned(),
            outputs: outputs.to_owned(),
            sparse_outputs: sparse_outputs.to_owned(),
            k,
            reminder,
            reminder_bits,
            prod,
            bits_info,
        }
    }
}

/// Evaluations at the same random point
#[derive(Serialize, Deserialize)]
pub struct LiftInstanceEval<F: Field> {
    /// input a in Zq
    pub input: F,
    /// output C = (c_0, ..., c_{N-1})^T \in F^{N * N}
    pub outputs: Vec<F>,
    /// We introduce witness k and r such that (2N/q) * a = k * N + r
    /// introduced witness k
    pub k: F,
    /// introduced witness reminder r
    pub reminder: F,
    /// decomposed bits of introduced reminder
    pub reminder_bits: Vec<F>,
    /// introduced witness prod denoted by s(x) = (r(x) + 1) * (1 - 2k(x))
    pub prod: F,
}

impl<F: Field> LiftInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + self.outputs.len() + self.reminder_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Flatten all evals into a vector with the same arrangement of the committed polynomial
    #[inline]
    pub fn flatten(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.num_oracles());
        res.push(self.input);
        res.extend(self.outputs.iter());
        res.push(self.k);
        res.push(self.reminder);
        res.extend(self.reminder_bits.iter());
        res.push(self.prod);
        res
    }

    /// Extract DecomposedBitsEval
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionEval<F> {
        BitDecompositionEval {
            d_val: vec![self.reminder],
            d_bits: self.reminder_bits.to_owned(),
        }
    }
}

/// IOP for transformation from Zq to RQ i.e. R/QR
#[derive(Default)]
pub struct LiftIOP<F: Field> {
    /// The random vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> LiftIOP<F> {
    /// Sample coins before proving sumcheck protocol
    ///
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The lift instance info.    
    pub fn sample_coins(trans: &mut Transcript<F>, info: &LiftInstanceInfo<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        )
    }

    /// Return the number of coins used in this IOP
    ///
    /// # Arguments.
    ///
    /// * `info` - The lift instance info.    
    pub fn num_coins(info: &LiftInstanceInfo<F>) -> usize {
        BitDecompositionIOP::<F>::num_coins(&info.bits_info) + 3
    }

    /// Generate the rlc randomenss.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The lift instance info.
    #[inline]
    pub fn generate_randomness(&mut self, trans: &mut Transcript<F>, info: &LiftInstanceInfo<F>) {
        self.randomness = Self::sample_coins(trans, info);
    }

    /// Generate the randomness for the eq function.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The lift instance info.
    #[inline]
    pub fn generate_randomness_for_eq_function(
        &mut self,
        trans: &mut Transcript<F>,
        info: &LiftInstanceInfo<F>,
    ) {
        self.u = trans.get_vec_challenge(
            b"LIFT IOP: random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// Lift IOP prover.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `instance` - The lift instance.
    pub fn prove(&self, trans: &mut Transcript<F>, instance: &LiftInstance<F>) -> SumcheckKit<F> {
        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);

        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));
        let matrix_at_u = Rc::new(gen_sparse_at_u(&instance.sparse_outputs, &self.u));

        let mut claimed_sum = F::zero();
        Self::prepare_products_of_polynomial(
            &self.randomness,
            &mut poly,
            &mut claimed_sum,
            instance,
            &matrix_at_u,
            &eq_at_u,
            &self.u,
        );

        let (proof, state) =
            MLSumcheck::prove(trans, &poly).expect("fail to prove the sumcheck protocol");
        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum,
            randomness: state.randomness,
            u: self.u.clone(),
        }
    }

    /// Add the sumcheck proving lift into the polynomial
    ///
    /// # Arguments.
    ///
    /// * `randomness` - The randomness used to randomnize the ntt instance.
    /// * `poly` - The list of product of polynomials.
    /// * `claimed_sum` - The claimed sum.
    /// * `instance` - The round instance.
    /// * `matrix_at_u` - The evaluation of matrix on point u.
    /// * `eq_at_u` - The evaluation of eq function on point u.
    /// * `u` - The randomness for eq.
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        claimed_sum: &mut F,
        instance: &LiftInstance<F>,
        matrix_at_u: &Rc<DenseMultilinearExtension<F>>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
        u: &[F],
    ) {
        let bits_instance = instance.extract_decomposed_bits();
        let bits_r_num = <BitDecompositionIOP<F>>::num_coins(&instance.bits_info);
        assert_eq!(randomness.len(), bits_r_num + 3);
        let (r_bits, r) = randomness.split_at(bits_r_num);
        // 1. add products used to prove decomposition
        BitDecompositionIOP::prepare_products_of_polynomial(r_bits, poly, &bits_instance, eq_at_u);

        // 2. add sumcheck \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l with random coefficient r[0]
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
                Rc::clone(&instance.k),
                Rc::clone(&instance.k),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (-F::one(), F::one()),
            ],
            r[0],
        );

        // 3. add sumcheck \sum_{x} eq(u, x) * [ (r(x) + 1) * (1 - 2k(x)) - s(x)]
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
                Rc::clone(&instance.reminder),
                Rc::clone(&instance.k),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::one()),
                (-F::one() - F::one(), F::one()),
            ],
            r[1],
        );
        poly.add_product([Rc::clone(eq_at_u), Rc::clone(&instance.prod)], -r[1]);

        // 4. add sumcheck \sum_y C(u, y)t(y) = s(u)
        poly.add_product(
            [
                Rc::clone(matrix_at_u),
                Rc::clone(&instance.info().generate_table()),
            ],
            r[2],
        );
        *claimed_sum += instance.prod.evaluate(u) * r[2];
    }

    /// Verify lift
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `wrapper` - The proof wrapper.
    /// * `evals_at_r` - The evaluations at random point r.
    /// * `evals_at_u` - The evaluations at random point u.
    /// * `info` - The list instance info.     
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &ProofWrapper<F>,
        evals_at_r: &LiftInstanceEval<F>,
        evals_at_u: &LiftInstanceEval<F>,
        info: &LiftInstanceInfo<F>,
    ) -> (bool, Vec<F>) {
        let mut subclaim =
            MLSumcheck::verify(trans, &wrapper.info, wrapper.claimed_sum, &wrapper.proof)
                .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&self.u, &subclaim.point);

        if !Self::verify_subclaim(
            &self.randomness,
            &mut subclaim,
            wrapper.claimed_sum,
            evals_at_r,
            evals_at_u,
            info,
            eq_at_u_r,
            &self.u,
        ) {
            return (false, vec![]);
        }

        let res = subclaim.expected_evaluations == F::zero();

        (res, subclaim.point)
    }

    /// Verify subclaim.
    ///
    /// # Arguments.
    ///
    /// * `randomness` - The randomness for rlc.
    /// * `subclaim` - The subclaim returned from the sumcheck protocol.
    /// * `claimed_sum` - The claimed sum.
    /// * `evals_at_r` - The evaluations at random point r.
    /// * `evals_at_u` - The evaluations at random point u.
    /// * `info` - The round instance info.
    /// * `eq_at_u_r` - The value eq(u,r).
    /// * `u` - The randomness for eq function.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        claimed_sum: F,
        evals_at_r: &LiftInstanceEval<F>,
        evals_at_u: &LiftInstanceEval<F>,
        info: &LiftInstanceInfo<F>,
        eq_at_u_r: F,
        u: &[F],
    ) -> bool {
        let bits_eval = evals_at_r.extract_decomposed_bits();
        let bits_r_num = <BitDecompositionIOP<F>>::num_coins(&info.bits_info);
        assert_eq!(randomness.len(), bits_r_num + 3);
        let (bits_r, r) = randomness.split_at(bits_r_num);
        // check 1: check the decomposed bits
        let check_bits = <BitDecompositionIOP<F>>::verify_subclaim(
            bits_r,
            subclaim,
            &bits_eval,
            &info.bits_info,
            eq_at_u_r,
        );
        if !check_bits {
            return false;
        }
        // check 2: check \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. w(x)\in\{0,1\}^l
        subclaim.expected_evaluations -=
            r[0] * eq_at_u_r * evals_at_r.k * (F::one() - evals_at_r.k);
        // check 3: check sumcheck \sum_{x} eq(u, x) * [ (r(x) + 1) * (1 - 2k(x)) - s(x)]
        let f_two = F::one() + F::one();
        subclaim.expected_evaluations -= r[1]
            * eq_at_u_r
            * ((evals_at_r.reminder + F::one()) * (F::one() - f_two * evals_at_r.k)
                - evals_at_r.prod);

        // check 4: check \sum_y C(u, y)t(y) = s(u)
        let num_vars = u.len();
        assert_eq!(evals_at_r.outputs.len(), 1 << num_vars);
        // c_r = C(x, r)
        let c_r = DenseMultilinearExtension::from_evaluations_slice(num_vars, &evals_at_r.outputs);
        subclaim.expected_evaluations -=
            c_r.evaluate(u) * info.generate_table().evaluate(&subclaim.point) * r[2];
        // TODO optimize evals_at_u to a single F, s(u)
        let mut res = claimed_sum == evals_at_u.prod * r[2];

        // check 5: (2N/q) * a = k * N + r
        res &= f_two * info.dim_rlwe * evals_at_r.input
            == (evals_at_r.k * info.dim_rlwe + evals_at_r.reminder) * info.q;

        res
    }
}

/// Lift proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct LiftProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Polynomial info.
    pub poly_info: PolynomialInfo,
    /// Polynomial commitment.
    pub poly_comm: Pcs::Commitment,
    /// The evaluation of the polynomial on r.
    pub oracle_eval_at_r: EF,
    /// The opening proof of the above evaluation.
    pub eval_proof_at_r: Pcs::Proof,
    /// The evaluation of the polynomial on u.
    pub oracle_eval_at_u: EF,
    /// The opening proof of the above evaluation.
    pub eval_proof_at_u: Pcs::Proof,
    /// The sumcheck proof.
    pub sumcheck_proof: sumcheck::Proof<EF>,
    /// The evaluation of small oracles.
    pub evals_at_r: LiftInstanceEval<EF>,
    /// The evaluation of small oracles.
    pub evals_at_u: LiftInstanceEval<EF>,
    /// Claimed sum in sumcheck.
    pub claimed_sum: EF,
}

impl<F, EF, S, Pcs> LiftProof<F, EF, S, Pcs>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// Lift parameter.
pub struct LiftParams<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// The parameter for the polynomial commitment.
    pub pp: Pcs::Parameters,
}

impl<F, EF, S, Pcs> Default for LiftParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        Self {
            pp: Pcs::Parameters::default(),
        }
    }
}

impl<F, EF, S, Pcs> LiftParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    #[inline]
    pub fn setup(&mut self, info: &LiftInstanceInfo<F>, code_spec: S) {
        self.pp = Pcs::setup(info.generate_num_var(), Some(code_spec));
    }
}

/// Prover for Lift with PCS.
pub struct LiftProver<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    _marker_f: PhantomData<F>,
    _marker_ef: PhantomData<EF>,
    _marker_s: PhantomData<S>,
    _marker_pcs: PhantomData<Pcs>,
}

impl<F, EF, S, Pcs> Default for LiftProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        LiftProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> LiftProver<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The prover.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `params` - The pcs params.
    /// * `instance` - The lift instance.
    pub fn prove(
        &self,
        trans: &mut Transcript<EF>,
        params: &LiftParams<F, EF, S, Pcs>,
        instance: &LiftInstance<F>,
    ) -> LiftProof<F, EF, S, Pcs> {
        let instance_info = instance.info();
        trans.append_message(b"lift instance", &instance_info);

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (poly_comm, poly_comm_state) = Pcs::commit(&params.pp, &committed_poly);

        trans.append_message(b"Lift IOP: polynomial commitment", &poly_comm);

        // Prover generates the proof.
        // Convert the orignal instance into an instance defined over EF.
        let instance_ef = instance.to_ef::<EF>();
        let instance_ef_info = instance_ef.info();
        let mut lift_iop = LiftIOP::<EF>::default();

        lift_iop.generate_randomness(trans, &instance_ef_info);
        lift_iop.generate_randomness_for_eq_function(trans, &instance_ef_info);

        let kit = lift_iop.prove(trans, &instance_ef);

        // Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let evals_at_r = instance.evaluate_ext(&kit.randomness);
        let evals_at_u = instance.evaluate_ext(&lift_iop.u);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = kit.randomness.clone();
        let mut requested_point_at_u = lift_iop.u.clone();
        let oracle_randomness = trans.get_vec_challenge(
            b"Lift IOP: random linear combination for evaluations of oracles",
            instance_info.log_num_oracles(),
        );

        requested_point_at_r.extend(oracle_randomness.iter());
        requested_point_at_u.extend(oracle_randomness.iter());
        let oracle_eval_at_r = committed_poly.evaluate_ext(&requested_point_at_r);
        let oracle_eval_at_u = committed_poly.evaluate_ext(&requested_point_at_u);

        // Generate the evaluation proof of the requested point
        let eval_proof_at_r = Pcs::open(
            &params.pp,
            &poly_comm,
            &poly_comm_state,
            &requested_point_at_r,
            trans,
        );
        let eval_proof_at_u = Pcs::open(
            &params.pp,
            &poly_comm,
            &poly_comm_state,
            &requested_point_at_u,
            trans,
        );

        LiftProof {
            poly_info: kit.info,
            poly_comm,
            oracle_eval_at_r,
            eval_proof_at_r,
            oracle_eval_at_u,
            eval_proof_at_u,
            sumcheck_proof: kit.proof,
            evals_at_r,
            evals_at_u,
            claimed_sum: kit.claimed_sum,
        }
    }
}

/// Verifier for Lift with PCS.
pub struct LiftVerifier<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    _marker_f: PhantomData<F>,
    _marker_ef: PhantomData<EF>,
    _marker_s: PhantomData<S>,
    _marker_pcs: PhantomData<Pcs>,
}

impl<F, EF, S, Pcs> Default for LiftVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        LiftVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> LiftVerifier<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The verifier.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `params` - The pcs params.
    /// * `info` - The lift instance info.
    /// * `proof` - The lift proof.
    pub fn verify(
        &self,
        trans: &mut Transcript<EF>,
        params: &LiftParams<F, EF, S, Pcs>,
        info: &LiftInstanceInfo<F>,
        proof: &LiftProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;
        trans.append_message(b"lift instance", info);
        trans.append_message(b"Lift IOP: polynomial commitment", &proof.poly_comm);

        let mut lift_iop = LiftIOP::<EF>::default();
        let info_ef = info.to_ef();

        lift_iop.generate_randomness(trans, &info_ef);
        lift_iop.generate_randomness_for_eq_function(trans, &info_ef);

        let proof_wrapper = ProofWrapper {
            claimed_sum: proof.claimed_sum,
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };

        let (b, randomness) = lift_iop.verify(
            trans,
            &proof_wrapper,
            &proof.evals_at_r,
            &proof.evals_at_u,
            &info_ef,
        );

        res &= b;

        // Check the relation between these small oracles and the committed oracle
        let flatten_evals_at_u = proof.evals_at_u.flatten();
        let flatten_evals_at_r = proof.evals_at_r.flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"Lift IOP: random linear combination for evaluations of oracles",
            proof.evals_at_u.log_num_oracles(),
        );

        let mut requested_point_at_r = randomness;
        let mut requested_point_at_u = lift_iop.u;

        requested_point_at_r.extend(&oracle_randomness);
        requested_point_at_u.extend(&oracle_randomness);

        res &= verify_oracle_relation(
            &flatten_evals_at_u,
            proof.oracle_eval_at_u,
            &oracle_randomness,
        );

        res &= verify_oracle_relation(
            &flatten_evals_at_r,
            proof.oracle_eval_at_r,
            &oracle_randomness,
        );

        // Check the evaluation of a random point over the committed oracle.
        res &= Pcs::verify(
            &params.pp,
            &proof.poly_comm,
            &requested_point_at_r,
            proof.oracle_eval_at_r,
            &proof.eval_proof_at_r,
            trans,
        );

        res &= Pcs::verify(
            &params.pp,
            &proof.poly_comm,
            &requested_point_at_u,
            proof.oracle_eval_at_u,
            &proof.eval_proof_at_u,
            trans,
        );

        res
    }
}

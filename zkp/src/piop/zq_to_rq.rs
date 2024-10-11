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
use super::{
    BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo,
};
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::{MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, gen_sparse_at_u, gen_sparse_at_u_to_ef,
    print_statistic, verify_oracle_relation,
};
use algebra::SparsePolynomial;
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials,
};
use core::fmt;
use itertools::izip;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;
use std::vec;
/// IOP for transformation from Zq to RQ i.e. R/QR
pub struct ZqToRQIOP<F: Field>(PhantomData<F>);

/// Snarks for transformation from Zq to RQ i.e. R/QR compiled with PCS
pub struct ZqToRQSnarks<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

/// Zq to RQ Instance.
/// In this instance, we require the outputs.len() == 1 << num_vars
pub struct ZqToRQInstance<F: Field> {
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

    /// We introduce witness k and r such that (2N/q) * a = k * N + r
    /// introduced witness k
    pub k: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness reminder r
    pub reminder: Rc<DenseMultilinearExtension<F>>,
    /// decomposed bits of introduced reminder
    pub reminder_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// introduced witness prod denoted by s(x) = (r(x) + 1) * (1 - 2k(x))
    pub prod: Rc<DenseMultilinearExtension<F>>,
    /// table [1, ..., N]
    pub table: Rc<DenseMultilinearExtension<F>>,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

/// Information of ZqToRQInstance
pub struct ZqToRQInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// modulus of Zq
    pub q: F,
    /// dimension of RWLE denoted by N
    pub dim_rlwe: F,
    /// table [1, ..., N]
    pub table: Rc<DenseMultilinearExtension<F>>,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for ZqToRQInstanceInfo<F> {
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

/// Evaluations at the same random point
pub struct ZqToRQInstanceEval<F: Field> {
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

impl<F: Field> ZqToRQInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> ZqToRQInstanceInfo<F> {
        ZqToRQInstanceInfo {
            num_vars: self.num_vars,
            q: self.q,
            dim_rlwe: self.dim_rlwe,
            bits_info: self.bits_info.clone(),
            table: self.table.clone(),
        }
    }

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
        let num_vars_added = self.log_num_oracles();
        let num_vars = self.num_vars + num_vars_added;
        let num_zeros_padded = ((1 << num_vars_added) - self.num_oracles()) * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> ZqToRQInstance<EF> {
        ZqToRQInstance::<EF> {
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
            table: Rc::new(self.table.to_ef::<EF>()),
        }
    }

    /// Evaluate at the same random point
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> ZqToRQInstanceEval<F> {
        ZqToRQInstanceEval {
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
    ) -> ZqToRQInstanceEval<EF> {
        ZqToRQInstanceEval {
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

impl<F: DecomposableField> ZqToRQInstance<F> {
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
        ZqToRQInstance {
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
            table: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars, table,
            )),
        }
    }
}

impl<F: Field> ZqToRQInstanceEval<F> {
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

impl<F: Field + Serialize> ZqToRQIOP<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &ZqToRQInstance<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <BitDecompositionIOP<F>>::num_coins(&instance.bits_info) + 3,
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &ZqToRQInstanceInfo<F>) -> usize {
        <BitDecompositionIOP<F>>::num_coins(&info.bits_info) + 3
    }

    /// Prove round
    pub fn prove(instance: &ZqToRQInstance<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        let matrix_at_u = Rc::new(gen_sparse_at_u(&instance.sparse_outputs, &u));

        let randomness = Self::sample_coins(&mut trans, instance);
        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        Self::prove_as_subprotocol(
            &randomness,
            &mut poly,
            &mut claimed_sum,
            instance,
            &matrix_at_u,
            &eq_at_u,
            &u,
        );

        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");
        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum,
            randomness: state.randomness,
            u,
        }
    }

    /// Add the sumchecks proving transformation from Zq to RQ
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        claimed_sum: &mut F,
        instance: &ZqToRQInstance<F>,
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
        poly.add_product([Rc::clone(matrix_at_u), Rc::clone(&instance.table)], r[2]);
        *claimed_sum += instance.prod.evaluate(u) * r[2];
    }

    /// Verify the transformation from Zq to RQ
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &ZqToRQInstanceEval<F>,
        evals_at_u: &ZqToRQInstanceEval<F>,
        info: &ZqToRQInstanceInfo<F>,
    ) -> bool {
        let mut trans = Transcript::new();

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        // randomness to combine sumcheck protocols
        let randomness = trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        );

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);

        if !Self::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &mut wrapper.claimed_sum,
            evals_at_r,
            evals_at_u,
            info,
            eq_at_u_r,
            &u,
        ) {
            return false;
        }

        subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()
    }

    /// Verify the transformation from Zq to RQ
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        claimed_sum: &mut F,
        evals_at_r: &ZqToRQInstanceEval<F>,
        evals_at_u: &ZqToRQInstanceEval<F>,
        info: &ZqToRQInstanceInfo<F>,
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
            c_r.evaluate(u) * info.table.evaluate(&subclaim.point) * r[2];
        // TODO optimize evals_at_u to a single F, s(u)
        *claimed_sum -= evals_at_u.prod * r[2];

        // check 5: (2N/q) * a = k * N + r
        f_two * info.dim_rlwe / info.q * evals_at_r.input
            == evals_at_r.k * info.dim_rlwe + evals_at_r.reminder
    }
}

impl<F, EF> ZqToRQSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &ZqToRQInstance<F>, code_spec: &S)
    where
        H: Hash + Sync + Send,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
        S: LinearCodeSpec<F, Code = C> + Clone,
    {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");
        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();
        // 1. Use PCS to commit the above polynomial.
        let start = Instant::now();
        let pp =
            BrakedownPCS::<F, H, C, S, EF>::setup(committed_poly.num_vars, Some(code_spec.clone()));
        let setup_time = start.elapsed().as_millis();

        let start = Instant::now();
        let (comm, comm_state) = BrakedownPCS::<F, H, C, S, EF>::commit(&pp, &committed_poly);
        let commit_time = start.elapsed().as_millis();

        // 2. Prover generates the proof
        let prover_start = Instant::now();
        let mut iop_proof_size = 0;
        let mut prover_trans = Transcript::<EF>::new();
        // Convert the original instance into an instance defined over EF
        let instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));
        let matrix_at_u = Rc::new(gen_sparse_at_u_to_ef(&instance.sparse_outputs, &prover_u));
        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let mut claimed_sum = EF::zero();
        let randomness = ZqToRQIOP::sample_coins(&mut prover_trans, &instance_ef);
        ZqToRQIOP::prove_as_subprotocol(
            &randomness,
            &mut sumcheck_poly,
            &mut claimed_sum,
            &instance_ef,
            &matrix_at_u,
            &eq_at_u,
            &prover_u,
        );

        let poly_info = sumcheck_poly.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        let evals_at_r = instance.evaluate_ext(&sumcheck_state.randomness);
        let evals_at_u = instance.evaluate_ext(&prover_u);

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = sumcheck_state.randomness.clone();
        let mut requested_point_at_u = prover_u.clone();
        let oracle_randomness = prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        );
        requested_point_at_r.extend(oracle_randomness.iter());
        requested_point_at_u.extend(oracle_randomness.iter());
        let oracle_eval_at_r = committed_poly.evaluate_ext(&requested_point_at_r);
        let oracle_eval_at_u = committed_poly.evaluate_ext(&requested_point_at_u);

        // 2.6 Generate the evaluation proof of the requested point
        let eval_proof_at_r = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &requested_point_at_r,
            &mut prover_trans,
        );
        let eval_proof_at_u = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &requested_point_at_u,
            &mut prover_trans,
        );
        let pcs_open_time = start.elapsed().as_millis();

        // 3. Verifier checks the proof
        let verifier_start = Instant::now();
        let mut verifier_trans = Transcript::<EF>::new();

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <ZqToRQIOP<EF>>::num_coins(&instance_info),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the sumcheck proof generated in Zq to RQ");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subcliam = ZqToRQIOP::<EF>::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &mut claimed_sum,
            &evals_at_r,
            &evals_at_u,
            &instance_info,
            eq_at_u_r,
            &verifier_u,
        );
        assert!(check_subcliam && subclaim.expected_evaluations == EF::zero());
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals_at_u = evals_at_u.flatten();
        let flatten_evals_at_r = evals_at_r.flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals_at_u.log_num_oracles(),
        );
        let check_oracle_at_u =
            verify_oracle_relation(&flatten_evals_at_u, oracle_eval_at_u, &oracle_randomness);
        let check_oracle_at_r =
            verify_oracle_relation(&flatten_evals_at_r, oracle_eval_at_r, &oracle_randomness);
        assert!(check_oracle_at_u && check_oracle_at_r);

        // 3.5 Check the evaluation of a random point over the committed oracle
        let check_pcs_at_r = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &requested_point_at_r,
            oracle_eval_at_r,
            &eval_proof_at_r,
            &mut verifier_trans,
        );
        let check_pcs_at_u = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &requested_point_at_u,
            oracle_eval_at_u,
            &eval_proof_at_u,
            &mut verifier_trans,
        );
        assert!(check_pcs_at_r && check_pcs_at_u);
        let pcs_verifier_time = start.elapsed().as_millis();
        pcs_proof_size += bincode::serialize(&eval_proof_at_r).unwrap().len()
            + bincode::serialize(&eval_proof_at_u).unwrap().len()
            + bincode::serialize(&flatten_evals_at_r).unwrap().len()
            + bincode::serialize(&flatten_evals_at_u).unwrap().len();

        // 4. print statistic
        print_statistic(
            iop_prover_time + pcs_open_time,
            iop_verifier_time + pcs_verifier_time,
            iop_proof_size + pcs_proof_size,
            iop_prover_time,
            iop_verifier_time,
            iop_proof_size,
            committed_poly.num_vars,
            instance.num_oracles(),
            instance.num_vars,
            setup_time,
            commit_time,
            pcs_open_time,
            pcs_verifier_time,
            pcs_proof_size,
        );
    }
}

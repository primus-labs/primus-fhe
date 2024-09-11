//! PIOP for Bit Decomposition (which could also be used for Range Check)
//! Define the structures required in SNARKs for Bit Decomposition
//! The prover wants to convince that the decomposition of an element into some bits on a power-of-two base.
//! * base (denoted by B): the power-of-two base used in bit decomposition
//! * base_len: the length of base, i.e. log_2(base)
//! * bits_len (denoted by l): the length of decomposed bits
//!
//! Given M instances of bit decomposition to be proved, d and each bit of d, i.e. (d_0, ..., d_l),
//! the main idea of this IOP is to prove:
//! For x \in \{0, 1\}^l
//! 1. d(x) = \sum_{i=0}^{log M - 1} B^i d_i(x) => can be reduced to the evaluation of a random point
//! 2. For every i \in \[l\]: \prod_{k = 0}^B (d_i(x) - k) = 0 =>
//!     a) each of which can be reduced to prove the following sum
//!        $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
//!        where u is the common random challenge from the verifier, used to instantiate every sum,
//!     b) and then, it can be proved with the sumcheck protocol where the maximum variable-degree is B + 1.
//!
//! The second part consists of l sumcheck protocols which can be combined into one giant sumcheck via random linear combination,
//! then the resulting purported sum is:
//! $\sum_{x \in \{0, 1\}^\log M} \sum_{i = 0}^{l-1} r_i \cdot eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
//! where r_i (for i = 0..l) are sampled from the verifier.
use crate::sumcheck::{verifier::SubClaim, MLSumcheck};
use crate::sumcheck::{ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, print_statistic, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, MultilinearExtension,
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

/// IOP for bit decomposition
pub struct BitDecomposition<F: Field>(PhantomData<F>);
/// SNARKs for bit decomposition compied with PCS
pub struct BitDecompositionSnarks<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);

/// Stores the parameters used for bit decomposation and every instance of decomposed bits,
/// and the batched polynomial used for the sumcheck protocol.
///
/// It is required to decompose over a power-of-2 base.
/// The resulting decomposed bits are used as the prover key.
pub struct DecomposedBits<F: Field> {
    /// base
    pub base: F,
    /// the length of base, i.e. log_2(base)
    pub base_len: usize,
    /// the length of decomposed bits
    pub bits_len: usize,
    /// number of variables of every polynomial
    pub num_vars: usize,
    /// batched values to be decomposed into bits
    pub d_val: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// batched plain deomposed bits, each of which corresponds to one bit decomposisiton instance
    pub d_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
}

/// Evaluations at a random point
pub struct DecomposedBitsEval<F: Field> {
    /// batched values to be decomposed into bits
    pub d_val: Vec<F>,
    /// batched plain deomposed bits, each of which corresponds to one bit decomposisiton instance
    pub d_bits: Vec<F>,
}

/// Stores the parameters used for bit decomposation.
///
/// * It is required to decompose over a power-of-2 base.
///
/// These parameters are used as the verifier key.
#[derive(Clone, Serialize)]
pub struct DecomposedBitsInfo<F: Field> {
    /// base
    pub base: F,
    /// the length of base, i.e. log_2(base)
    pub base_len: usize,
    /// the length of decomposed bits (denoted by l)
    pub bits_len: usize,
    /// number of variables of every polynomial
    pub num_vars: usize,
    /// number of instances
    pub num_instances: usize,
}

impl<F: Field> fmt::Display for DecomposedBitsInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} instances of Decomposed Bits: #vars = {}, base = 2^{}, #bits = {}",
            self.num_instances, self.num_vars, self.base_len, self.bits_len
        )
    }
}

impl<F: Field> DecomposedBitsInfo<F> {
    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> DecomposedBitsInfo<EF> {
        DecomposedBitsInfo::<EF> {
            base: EF::from_base(self.base),
            base_len: self.base_len,
            bits_len: self.bits_len,
            num_vars: self.num_vars,
            num_instances: self.num_instances,
        }
    }
}

impl<F: Field> DecomposedBits<F> {
    #[inline]
    /// Extract the information of decomposed bits for verification
    pub fn info(&self) -> DecomposedBitsInfo<F> {
        DecomposedBitsInfo {
            base: self.base,
            base_len: self.base_len,
            bits_len: self.bits_len,
            num_vars: self.num_vars,
            num_instances: self.d_val.len(),
        }
    }

    /// Initiate the polynomial used for sumcheck protocol
    #[inline]
    pub fn new(base: F, base_len: usize, bits_len: usize, num_vars: usize) -> Self {
        DecomposedBits {
            base,
            base_len,
            bits_len,
            num_vars,
            d_val: Vec::new(),
            d_bits: Vec::new(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        // number of value oracle + number of decomposed bits oracle
        self.d_val.len() + self.d_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    #[inline]
    /// Add one bit decomposition instance, meaning to add l sumcheck protocols.
    /// * decomposed_bits: store each bit
    pub fn add_decomposed_bits_instance(
        &mut self,
        d_val: &Rc<DenseMultilinearExtension<F>>,
        decomposed_bits: &[Rc<DenseMultilinearExtension<F>>],
    ) {
        assert_eq!(decomposed_bits.len(), self.bits_len);
        for bit in decomposed_bits {
            assert_eq!(bit.num_vars, self.num_vars);
        }
        self.d_bits.extend(decomposed_bits.to_owned());
        self.d_val.push(Rc::clone(d_val));
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_all_mles(&self) -> Vec<F> {
        assert_eq!(self.d_val.len() * self.bits_len, self.d_bits.len());

        // arrangement: all values||all decomposed bits
        self.d_val
            .iter()
            .flat_map(|d| d.iter())
            // concatenated with decomposed bits
            .chain(self.d_bits.iter().flat_map(|bit| bit.iter()))
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    #[inline]
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
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> DecomposedBits<EF> {
        DecomposedBits::<EF> {
            num_vars: self.num_vars,
            base: EF::from_base(self.base),
            base_len: self.base_len,
            bits_len: self.bits_len,
            d_val: self
                .d_val
                .iter()
                .map(|val| Rc::new(val.to_ef()))
                .collect::<Vec<_>>(),
            d_bits: self
                .d_bits
                .iter()
                .map(|bit| Rc::new(bit.to_ef()))
                .collect::<Vec<_>>(),
        }
    }

    /// Evaluate at a random point defined over Field
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> DecomposedBitsEval<F> {
        DecomposedBitsEval::<F> {
            d_val: self.d_val.iter().map(|val| val.evaluate(point)).collect(),
            d_bits: self.d_bits.iter().map(|bit| bit.evaluate(point)).collect(),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> DecomposedBitsEval<EF> {
        DecomposedBitsEval::<EF> {
            d_val: self
                .d_val
                .iter()
                .map(|val| val.evaluate_ext(point))
                .collect(),
            d_bits: self
                .d_bits
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        eq_at_r: &DenseMultilinearExtension<EF>,
    ) -> DecomposedBitsEval<EF> {
        DecomposedBitsEval::<EF> {
            d_val: self
                .d_val
                .iter()
                .map(|val| val.evaluate_ext_opt(eq_at_r))
                .collect(),
            d_bits: self
                .d_bits
                .iter()
                .map(|bit| bit.evaluate_ext_opt(eq_at_r))
                .collect(),
        }
    }
}

impl<F: DecomposableField> DecomposedBits<F> {
    /// Use the base defined in this instance to perform decomposition over the input value.
    /// Then add the result into this instance, meaning to add l sumcheck protocols.
    /// * decomposed_bits: store each bit
    #[inline]
    pub fn add_value_instance(&mut self, value: &DenseMultilinearExtension<F>) {
        assert_eq!(self.num_vars, value.num_vars);
        let mut bits = value.get_decomposed_mles(self.base_len, self.bits_len);
        self.d_bits.append(&mut bits);
    }
}

impl<F: Field> DecomposedBitsEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        // number of value oracle + number of decomposed bits oracle
        self.d_val.len() + self.d_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Flatten all evals into a vector with the same arrangement of the committed polynomial
    #[inline]
    pub fn flatten(&self) -> Vec<F> {
        self.d_val
            .iter()
            .chain(self.d_bits.iter())
            .copied()
            .collect()
    }
}

impl<F: Field + Serialize> BitDecomposition<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &DecomposedBits<F>) -> Vec<F> {
        // batch `len_bits` sumcheck protocols into one with random linear combination
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            instance.d_bits.len(),
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &DecomposedBitsInfo<F>) -> usize {
        info.bits_len * info.num_instances
    }

    /// Prove bit decomposition given the decomposed bits as prover key.
    pub fn prove(instance: &DecomposedBits<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        // randomness to combine sumcheck protocols
        let randomness = Self::sample_coins(&mut trans, instance);
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) = MLSumcheck::prove_as_subprotocol(&mut trans, &poly)
            .expect("fail to prove the sumcheck protocol");

        SumcheckKit {
            proof,
            randomness: state.randomness,
            claimed_sum: F::zero(),
            info: poly.info(),
            u,
        }
    }

    /// Prove bit decomposition given the decomposed bits as prover key.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &DecomposedBits<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let base = 1 << instance.base_len;

        // For every bit, the reduced sum is $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] = 0$
        // and the added product is r_i \cdot eq(u, x) \cdot [\prod_{k=0}^B (d_i(x) - k)] with the corresponding randomness
        for (r, bit) in izip!(randomness, instance.d_bits.iter()) {
            let mut product: Vec<_> = Vec::with_capacity(base + 1);
            let mut op_coefficient: Vec<_> = Vec::with_capacity(base + 1);
            product.push(Rc::clone(eq_at_u));
            op_coefficient.push((F::one(), F::zero()));

            let mut minus_k = F::zero();
            for _ in 0..base {
                product.push(Rc::clone(bit));
                op_coefficient.push((F::one(), minus_k));
                minus_k -= F::one();
            }
            poly.add_product_with_linear_op(product, &op_coefficient, *r);
        }
    }

    /// Verify bit decomposition given the basic information of decomposed bits as verifier key.
    pub fn verify(
        wrapper: &ProofWrapper<F>,
        evals: &DecomposedBitsEval<F>,
        info: &DecomposedBitsInfo<F>,
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

        let mut subclaim =
            MLSumcheck::verify_as_subprotocol(&mut trans, &wrapper.info, F::zero(), &wrapper.proof)
                .expect("fail to verify the sumcheck protocol");

        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);
        if !Self::verify_as_subprotocol(&randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return false;
        }

        subclaim.expected_evaluations == F::zero()
    }

    /// Verify bit decomposition
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &DecomposedBitsEval<F>,
        info: &DecomposedBitsInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        assert_eq!(evals.d_val.len(), info.num_instances);
        assert_eq!(evals.d_bits.len(), info.num_instances * info.bits_len);
        // base_pow = [1, B, ..., B^{l-1}]
        let mut base_pow = vec![F::one(); info.bits_len];
        base_pow.iter_mut().fold(F::one(), |acc, pow| {
            *pow *= acc;
            acc * info.base
        });

        // check 1: d[point] = \sum_{i=0}^len B^i \cdot d_i[point] for every instance
        if !evals
            .d_val
            .iter()
            .zip(evals.d_bits.chunks_exact(info.bits_len))
            .all(|(val, bits)| {
                *val == bits
                    .iter()
                    .zip(base_pow.iter())
                    .fold(F::zero(), |acc, (bit, pow)| acc + *bit * *pow)
            })
        {
            return false;
        }

        // check 2: expected value returned in sumcheck
        // each instance contributes value: eq(u, x) \cdot \sum_{i = 0}^{l-1} r_i \cdot [\prod_{k=0}^B (d_i(x) - k)] =? expected_evaluation
        let mut real_eval = F::zero();
        for (r, bit) in izip!(randomness, &evals.d_bits) {
            let mut prod = *r;
            let mut minus_k = F::zero();
            for _ in 0..(1 << info.base_len) {
                prod *= *bit + minus_k;
                minus_k -= F::one();
            }
            real_eval += prod;
        }
        subclaim.expected_evaluations -= real_eval * eq_at_u_r;

        true
    }
}

impl<F, EF> BitDecompositionSnarks<F, EF>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &DecomposedBits<F>, code_spec: &S)
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

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let claimed_sum = EF::zero();
        let randomness = BitDecomposition::sample_coins(&mut prover_trans, &instance_ef);
        BitDecomposition::prove_as_subprotocol(
            &randomness,
            &mut sumcheck_poly,
            &instance_ef,
            &eq_at_u,
        );

        let poly_info = sumcheck_poly.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove_as_subprotocol(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        let eq_at_r = gen_identity_evaluations(&sumcheck_state.randomness);
        // let evals = instance.evaluate_ext(&sumcheck_state.randomness);
        let evals = instance.evaluate_ext_opt(&eq_at_r);
        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point = sumcheck_state.randomness.clone();
        requested_point.extend(&prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        ));
        let oracle_eval = committed_poly.evaluate_ext(&requested_point);

        // 2.6 Generate the evaluation proof of the requested point
        let eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &requested_point,
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
            <BitDecomposition<EF>>::num_coins(&instance_info),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify_as_subprotocol(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in Bit Decompositon");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subcliam = BitDecomposition::<EF>::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &evals,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subcliam && subclaim.expected_evaluations == EF::zero());
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals = evals.flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals.log_num_oracles(),
        );
        let check_oracle = verify_oracle_relation(&flatten_evals, oracle_eval, &oracle_randomness);
        assert!(check_oracle);

        // 3.5 Check the evaluation of a random point over the committed oracle

        let check_pcs = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &requested_point,
            oracle_eval,
            &eval_proof,
            &mut verifier_trans,
        );
        assert!(check_pcs);
        let pcs_verifier_time = start.elapsed().as_millis();
        pcs_proof_size += bincode::serialize(&eval_proof).unwrap().len()
            + bincode::serialize(&flatten_evals).unwrap().len();

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
        )
    }
}

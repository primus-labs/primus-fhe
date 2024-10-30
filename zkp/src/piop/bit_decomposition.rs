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
use crate::sumcheck::{self, verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{eval_identity_function, gen_identity_evaluations, verify_oracle_relation};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use bincode::Result;
use core::fmt;
use itertools::izip;
use pcs::PolynomialCommitmentScheme;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc};

use super::LookupInstance;

/// Stores the parameters used for bit decomposation and every instance of decomposed bits,
/// and the batched polynomial used for the sumcheck protocol.
///
/// It is required to decompose over a power-of-2 base.
/// The resulting decomposed bits are used as the prover key.
pub struct BitDecompositionInstance<F: Field> {
    /// The power-of-two base
    pub base: F,
    /// The length of the base, i.e. log_2(base)
    pub base_len: usize,
    /// The length of decomposed bits
    pub bits_len: usize,
    /// The number of variables of every polynomial
    pub num_vars: usize,
    /// The batched values to be decomposed into bits
    pub d_val: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// The batched plain deomposed bits, each of which corresponds to one bit decomposisiton instance
    pub d_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
}

/// Evaluations at a random point
#[derive(Serialize, Deserialize)]
pub struct BitDecompositionEval<F: Field> {
    /// The batched values to be decomposed into bits
    pub d_val: Vec<F>,
    /// The batched plain deomposed bits, each of which corresponds to one bit decomposisiton instance
    pub d_bits: Vec<F>,
}

/// Stores the parameters used for bit decomposation.
///
/// * It is required to decompose over a power-of-2 base.
///
/// These parameters are used as the verifier key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitDecompositionInstanceInfo<F: Field> {
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

impl<F: Field> fmt::Display for BitDecompositionInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} instances of Decomposed Bits: #vars = {}, base = 2^{}, #bits = {}",
            self.num_instances, self.num_vars, self.base_len, self.bits_len
        )
    }
}

impl<F: Field> BitDecompositionInstanceInfo<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        // number of value oracle + number of decomposed bits oracle
        self.num_instances + self.num_instances * self.bits_len
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
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> BitDecompositionInstanceInfo<EF> {
        BitDecompositionInstanceInfo::<EF> {
            base: EF::from_base(self.base),
            base_len: self.base_len,
            bits_len: self.bits_len,
            num_vars: self.num_vars,
            num_instances: self.num_instances,
        }
    }
}

impl<F: Field> BitDecompositionInstance<F> {
    #[inline]
    /// Extract the information of decomposed bits for verification
    pub fn info(&self) -> BitDecompositionInstanceInfo<F> {
        BitDecompositionInstanceInfo {
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
        BitDecompositionInstance {
            base,
            base_len,
            bits_len,
            num_vars,
            d_val: Vec::new(),
            d_bits: Vec::new(),
        }
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
        let info = self.info();
        let num_vars = info.generate_num_var();
        let num_zeros_padded = (1 << num_vars) - info.num_oracles() * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> BitDecompositionInstance<EF> {
        BitDecompositionInstance::<EF> {
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
    pub fn evaluate(&self, point: &[F]) -> BitDecompositionEval<F> {
        BitDecompositionEval::<F> {
            d_val: self.d_val.iter().map(|val| val.evaluate(point)).collect(),
            d_bits: self.d_bits.iter().map(|bit| bit.evaluate(point)).collect(),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> BitDecompositionEval<EF> {
        BitDecompositionEval::<EF> {
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
    ) -> BitDecompositionEval<EF> {
        BitDecompositionEval::<EF> {
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

    /// Extract the lookup instance
    #[inline]
    pub fn extract_lookup_instance(&self, block_size: usize) -> LookupInstance<F> {
        let mut table = vec![F::zero(); 1 << self.num_vars];
        let mut acc = F::zero();
        for t in table.iter_mut().take(1 << self.base_len) {
            *t = acc;
            acc += F::one();
        }
        let table = DenseMultilinearExtension::from_evaluations_vec(self.num_vars, table);

        LookupInstance::from_slice(
            &self
                .d_bits
                .iter()
                .map(|d| d.as_ref().clone())
                .collect::<Vec<_>>(),
            table,
            block_size,
        )
    }
}

impl<F: DecomposableField> BitDecompositionInstance<F> {
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

impl<F: Field> BitDecompositionEval<F> {
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

/// IOP for bit decomposition
#[derive(Default)]
pub struct BitDecompositionIOP<F: Field> {
    /// The random vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> BitDecompositionIOP<F> {
    /// Sample coins before proving sumcheck protocol
    #[inline]
    pub fn sample_coins(
        trans: &mut Transcript<F>,
        info: &BitDecompositionInstanceInfo<F>,
    ) -> Vec<F> {
        // Batch `len_bits` sumcheck protocols into one with random linear combination
        trans.get_vec_challenge(
            b"BD IOP: randomness to combine sumcheck protocols",
            Self::num_coins(info),
        )
    }

    /// Return the number of coins used in this IOP
    #[inline]
    pub fn num_coins(info: &BitDecompositionInstanceInfo<F>) -> usize {
        info.bits_len * info.num_instances
    }

    /// Generate the randomenss.
    #[inline]
    pub fn generate_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        info: &BitDecompositionInstanceInfo<F>,
    ) {
        self.randomness = Self::sample_coins(trans, info);
    }

    /// Generate the randomness for the eq function.
    #[inline]
    pub fn generate_randomness_for_eq_function(
        &mut self,
        trans: &mut Transcript<F>,
        info: &BitDecompositionInstanceInfo<F>,
    ) {
        self.u = trans.get_vec_challenge(
            b"BD IOP: random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// BitDecomposition IOP prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &BitDecompositionInstance<F>,
    ) -> SumcheckKit<F> {
        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);

        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));

        Self::prepare_products_of_polynomial(&self.randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) =
            MLSumcheck::prove(trans, &poly).expect("fail to prove the sumcheck protocol");

        SumcheckKit {
            proof,
            randomness: state.randomness,
            claimed_sum: F::zero(),
            info: poly.info(),
            u: self.u.clone(),
        }
    }

    /// Prove bit decomposition given the decomposed bits as prover key.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &BitDecompositionInstance<F>,
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
        &self,
        trans: &mut Transcript<F>,
        wrapper: &ProofWrapper<F>,
        evals: &BitDecompositionEval<F>,
        info: &BitDecompositionInstanceInfo<F>,
    ) -> (bool, Vec<F>) {
        let mut subclaim = MLSumcheck::verify(trans, &wrapper.info, F::zero(), &wrapper.proof)
            .expect("fail to verify the sumcheck protocol");

        let eq_at_u_r = eval_identity_function(&self.u, &subclaim.point);
        if !Self::verify_subclaim(&self.randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return (false, vec![]);
        }

        (subclaim.expected_evaluations == F::zero(), subclaim.point)
    }

    /// Verify bit decomposition relation without verifying each bit < base
    pub fn verify_subclaim_without_range_check(
        evals: &BitDecompositionEval<F>,
        info: &BitDecompositionInstanceInfo<F>,
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
        evals
            .d_val
            .iter()
            .zip(evals.d_bits.chunks_exact(info.bits_len))
            .all(|(val, bits)| {
                *val == bits
                    .iter()
                    .zip(base_pow.iter())
                    .fold(F::zero(), |acc, (bit, pow)| acc + *bit * *pow)
            })
    }

    /// Verify bit decomposition
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &BitDecompositionEval<F>,
        info: &BitDecompositionInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        // check 1: d[point] = \sum_{i=0}^len B^i \cdot d_i[point] for every instance
        if !Self::verify_subclaim_without_range_check(evals, info) {
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

/// Bit decomposition proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct BitDecompositionProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Polynomial info
    pub poly_info: PolynomialInfo,
    /// Polynomial commitment.
    pub poly_comm: Pcs::Commitment,
    /// The evaluation of the polynomial.
    pub oracle_eval: EF,
    /// The opening proof of the polynomial.
    pub eval_proof: Pcs::Proof,
    /// The sumcheck proof.
    pub sumcheck_proof: sumcheck::Proof<EF>,
    /// The evaluations.
    pub evals: BitDecompositionEval<EF>,
}

impl<F, EF, S, Pcs> BitDecompositionProof<F, EF, S, Pcs>
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

/// BitDecomposition parameter.
pub struct BitDecompositionParams<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// The parameter for the polynomial commitment.
    pub pp: Pcs::Parameters,
}

impl<F, EF, S, Pcs> Default for BitDecompositionParams<F, EF, S, Pcs>
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

impl<F, EF, S, Pcs> BitDecompositionParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    #[inline]
    pub fn setup(&mut self, info: &BitDecompositionInstanceInfo<F>, code_spec: S) {
        self.pp = Pcs::setup(info.generate_num_var(), Some(code_spec));
    }
}

/// Prover for bit decomposition with PCS.
pub struct BitDecompositionProver<
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

impl<F, EF, S, Pcs> Default for BitDecompositionProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        BitDecompositionProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> BitDecompositionProver<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<EF>,
        params: &BitDecompositionParams<F, EF, S, Pcs>,
        instance: &BitDecompositionInstance<F>,
    ) -> BitDecompositionProof<F, EF, S, Pcs> {
        let instance_info = instance.info();

        trans.append_message(b"bit decomposition instance", &instance_info);

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (poly_comm, poly_comm_state) = Pcs::commit(&params.pp, &committed_poly);

        trans.append_message(b"BD IOP: polynomial commitment", &poly_comm);

        // Prover generates the proof.
        // Convert the orignal instance into an instance defined over EF.
        let instance_ef = instance.to_ef::<EF>();
        let instance_ef_info = instance_ef.info();
        let mut bd_iop = BitDecompositionIOP::<EF>::default();

        bd_iop.generate_randomness(trans, &instance_ef_info);
        bd_iop.generate_randomness_for_eq_function(trans, &instance_ef_info);
        let kit = bd_iop.prove(trans, &instance_ef);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point = kit.randomness.clone();
        let oracle_randomness = trans.get_vec_challenge(
            b"BD IOP: random linear combinaiton for evaluations of the oracles",
            instance_info.log_num_oracles(),
        );
        requested_point.extend(&oracle_randomness);

        // Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let evals = instance_ef.evaluate(&kit.randomness);

        let oracle_eval = committed_poly.evaluate_ext(&requested_point);

        // Generate the evaluation proof of the requested point.
        let eval_proof = Pcs::open(
            &params.pp,
            &poly_comm,
            &poly_comm_state,
            &requested_point,
            trans,
        );

        BitDecompositionProof {
            poly_info: kit.info,
            poly_comm,
            oracle_eval,
            eval_proof,
            sumcheck_proof: kit.proof,
            evals,
        }
    }
}

/// Verifier for bit decomposition with PCS.
pub struct BitDecompositionVerifier<
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

impl<F, EF, S, Pcs> Default for BitDecompositionVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        BitDecompositionVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> BitDecompositionVerifier<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The verifier.
    pub fn verify(
        &self,
        trans: &mut Transcript<EF>,
        params: &BitDecompositionParams<F, EF, S, Pcs>,
        info: &BitDecompositionInstanceInfo<F>,
        proof: &BitDecompositionProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"bit decomposition instance", info);
        trans.append_message(b"BD IOP: polynomial commitment", &proof.poly_comm);

        let mut bd_iop = BitDecompositionIOP::<EF>::default();
        let info_ef = info.to_ef();

        bd_iop.generate_randomness(trans, &info_ef);
        bd_iop.generate_randomness_for_eq_function(trans, &info_ef);

        let proof_wrapper = ProofWrapper {
            claimed_sum: EF::zero(),
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };

        let (b, randomness) = bd_iop.verify(trans, &proof_wrapper, &proof.evals, &info.to_ef());

        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let flatten_evals = proof.evals.flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"BD IOP: random linear combinaiton for evaluations of the oracles",
            proof.evals.log_num_oracles(),
        );
        res &= verify_oracle_relation(&flatten_evals, proof.oracle_eval, &oracle_randomness);

        // Check the evaluation of a random point over the committed oracle.
        let mut requested_point = randomness.clone();
        requested_point.extend(&oracle_randomness);
        res &= Pcs::verify(
            &params.pp,
            &proof.poly_comm,
            &requested_point,
            proof.oracle_eval,
            &proof.eval_proof,
            trans,
        );

        res
    }
}

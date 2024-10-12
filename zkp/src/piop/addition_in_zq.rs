//! PIOP for Addition in Zq
//! The prover wants to convince that the addition in Zq in a larger modulus Q.
//! * q: the modulus used in the addition
//!
//! Given M instances of addition in Zq, the main idea of this IOP is to prove:
//! For x \in \{0, 1\}^l
//! 1. a(x), b(c), c(x) \in \[q\] => these range check can be batchly proved by the Bit Decomposition IOP
//! 2. k(x) \cdot (1 - k(x)) = 0  => can be reduced to prove the sum
//!     $\sum_{x \in \{0, 1\}^\log M} eq(u, x) \cdot [k(x) \cdot (1 - k(x))] = 0$
//!     where u is the common random challenge from the verifier, used to instantiate the sum,
//!     and then, it can be proved with the sumcheck protocol where the maximum variable-degree is 3.
//! 3. a(x) + b(x) = c(x) + k(x)\cdot q => can be reduced to the evaluation of a random point since the LHS and RHS are both MLE
use crate::piop::LookupIOP;
use crate::sumcheck::{self, verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, print_statistic, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use bincode::Result;
use core::fmt;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc, time::Instant};

use super::{
    BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo, LookupInstance,
};

/// SNARKs for addition in Zq compiled with PCS
pub struct AdditionInZqSnarks<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);

/// IOP for addition in Zq, i.e. a + b = c (mod q)
pub struct AdditionInZqPure<F: Field>(PhantomData<F>);
/// SNARKs for addition in Zq compiled with PCS
pub struct AdditionInZqSnarksOpt<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);

/// Stores the parameters used for addition in Zq and the inputs and witness for prover.
pub struct AdditionInZqInstance<F: Field> {
    /// The modulus in addition
    pub q: F,
    /// The number of variables
    pub num_vars: usize,
    /// The inputs a, b, and c
    pub abc: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// The introduced witness k
    pub k: Rc<DenseMultilinearExtension<F>>,
    /// The introduced witness to check the range of a, b, c
    pub abc_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// The info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

/// Evaluations of all MLEs involved in the instance at a random point
#[derive(Serialize, Deserialize)]
pub struct AdditionInZqInstanceEval<F: Field> {
    /// inputs a, b, and c
    pub abc: Vec<F>,
    /// introduced witness k
    pub k: F,
    /// introduced witness to check the range of a, b, c
    pub abc_bits: Vec<F>,
}

/// Stores the parameters used for addition in Zq and the public info for verifier.
#[derive(Serialize, Deserialize)]
pub struct AdditionInZqInstanceInfo<F: Field> {
    /// The modulus in addition
    pub q: F,
    /// The number of variables
    pub num_vars: usize,
    /// Decomposition info for range check (i.e. bit decomposition)
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for AdditionInZqInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "An instance of Addition In Zq: #vars = {}, q = {}",
            self.num_vars, self.q,
        )?;
        write!(f, "- containing ")?;
        self.bits_info.fmt(f)
    }
}

impl<F: Field> AdditionInZqInstanceInfo<F> {
    /// Construct an EF version.
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> AdditionInZqInstanceInfo<EF> {
        AdditionInZqInstanceInfo::<EF> {
            q: EF::from_base(self.q),
            num_vars: self.num_vars,
            bits_info: self.bits_info.to_ef(),
        }
    }
}

impl<F: Field> AdditionInZqInstance<F> {
    /// Extract the information of addition in Zq for verification
    #[inline]
    pub fn info(&self) -> AdditionInZqInstanceInfo<F> {
        AdditionInZqInstanceInfo {
            q: self.q,
            num_vars: self.num_vars,
            bits_info: self.bits_info.clone(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        assert_eq!(self.abc.len(), 3);
        assert_eq!(self.abc_bits.len(), 3 * self.bits_info.bits_len);
        self.abc.len() + 1 + self.abc_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_all_mles(&self) -> Vec<F> {
        // arrangement: abc || k || abc_bits
        self.abc
            .iter()
            .flat_map(|v| v.iter())
            .chain(self.k.iter())
            .chain(self.abc_bits.iter().flat_map(|bit| bit.iter()))
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the number of variables in the commited polynomial.
    #[inline]
    pub fn generate_num_var(&self) -> usize {
        self.num_vars + self.log_num_oracles()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    #[inline]
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars = self.generate_num_var();
        let num_zeros_padded = (1 << num_vars) - self.num_oracles() * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> AdditionInZqInstance<EF> {
        AdditionInZqInstance::<EF> {
            q: EF::from_base(self.q),
            num_vars: self.num_vars,
            abc: self.abc.iter().map(|v| Rc::new(v.to_ef())).collect(),
            k: Rc::new(self.k.to_ef()),
            abc_bits: self
                .abc_bits
                .iter()
                .map(|bit| Rc::new(bit.to_ef()))
                .collect(),
            bits_info: self.bits_info.to_ef::<EF>(),
        }
    }

    /// Evaluate at a random point defined over Field
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> AdditionInZqInstanceEval<F> {
        AdditionInZqInstanceEval::<F> {
            abc: self.abc.iter().map(|v| v.evaluate(point)).collect(),
            k: self.k.evaluate(point),
            abc_bits: self
                .abc_bits
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> AdditionInZqInstanceEval<EF> {
        AdditionInZqInstanceEval::<EF> {
            abc: self.abc.iter().map(|v| v.evaluate_ext(point)).collect(),
            k: self.k.evaluate_ext(point),
            abc_bits: self
                .abc_bits
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
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
            d_val: self.abc.to_owned(),
            d_bits: self.abc_bits.to_owned(),
        }
    }

    /// Extract lookup instance
    #[inline]
    pub fn extract_lookup_instance(&self, block_size: usize) -> LookupInstance<F> {
        self.extract_decomposed_bits()
            .extract_lookup_instance(block_size)
    }
}

impl<F: Field> AdditionInZqInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        // number of value oracle + number of decomposed bits oracle
        self.abc.len() + 1 + self.abc_bits.len()
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
        res.extend(self.abc.iter());
        res.push(self.k);
        res.extend(self.abc_bits.iter());
        res
    }

    /// Extract DecomposedBitsEval instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionEval<F> {
        BitDecompositionEval {
            d_val: self.abc.to_owned(),
            d_bits: self.abc_bits.to_owned(),
        }
    }
}

impl<F: DecomposableField> AdditionInZqInstance<F> {
    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        abc: &[Rc<DenseMultilinearExtension<F>>],
        k: &Rc<DenseMultilinearExtension<F>>,
        q: F,
        bits_info: &BitDecompositionInstanceInfo<F>,
    ) -> Self {
        let num_vars = k.num_vars;
        assert_eq!(abc.len(), 3);
        assert_eq!(bits_info.num_instances, 3);
        for x in abc {
            assert_eq!(x.num_vars, num_vars);
        }

        let abc_bits = abc
            .iter()
            .flat_map(|x| x.get_decomposed_mles(bits_info.base_len, bits_info.bits_len))
            .collect();

        Self {
            q,
            num_vars,
            abc: abc.to_owned(),
            k: Rc::clone(k),
            abc_bits,
            bits_info: bits_info.clone(),
        }
    }
}

/// IOP for addition in Zq, i.e. a + b = c (mod q)
#[derive(Default)]
pub struct AdditionInZqIOP<F: Field> {
    /// The randomness vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> AdditionInZqIOP<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, info: &AdditionInZqInstanceInfo<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        )
    }

    /// return the number of coins used in this IOP
    #[inline]
    pub fn num_coins(info: &AdditionInZqInstanceInfo<F>) -> usize {
        <BitDecompositionIOP<F>>::num_coins(&info.bits_info) + 1
    }

    /// Generate the randomness
    #[inline]
    pub fn generate_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        info: &AdditionInZqInstanceInfo<F>,
    ) {
        self.randomness = Self::sample_coins(trans, info);
        self.u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// AdditionInZqIOP prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &AdditionInZqInstance<F>,
    ) -> SumcheckKit<F> {
        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));
        Self::prepare_products_of_polynomial(&self.randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) =
            MLSumcheck::prove(trans, &poly).expect("fail to prove the sumcheck protocol");

        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum: F::zero(),
            randomness: state.randomness,
            u: self.u.clone(),
        }
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &AdditionInZqInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let bits_instance = instance.extract_decomposed_bits();
        let bits_info = bits_instance.info();
        let bits_r_num = <BitDecompositionIOP<F>>::num_coins(&bits_info);
        // 1. add products of poly used to prove decomposition
        BitDecompositionIOP::prepare_products_of_polynomial(
            &randomness[..bits_r_num],
            poly,
            &bits_instance,
            eq_at_u,
        );

        // 2. sumcheck for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l
        let coin = randomness[randomness.len() - 1];
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
            coin,
        );
    }

    /// Verify addition in Zq
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &ProofWrapper<F>,
        evals: &AdditionInZqInstanceEval<F>,
        info: &AdditionInZqInstanceInfo<F>,
    ) -> (bool, Vec<F>) {
        let mut subclaim = MLSumcheck::verify(trans, &wrapper.info, F::zero(), &wrapper.proof)
            .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&self.u, &subclaim.point);

        if !Self::verify_subclaim(&self.randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return (false, vec![]);
        }

        (subclaim.expected_evaluations == F::zero(), subclaim.point)
    }

    /// Verify the subclaim.
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &AdditionInZqInstanceEval<F>,
        info: &AdditionInZqInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        // check 1: Verify the range check part in the sumcheck polynomial
        let bits_evals = evals.extract_decomposed_bits();
        let bits_randomness = &randomness[..<BitDecompositionIOP<F>>::num_coins(&info.bits_info)];
        let check_decomposed_bits = <BitDecompositionIOP<F>>::verify_subclaim(
            bits_randomness,
            subclaim,
            &bits_evals,
            &info.bits_info,
            eq_at_u_r,
        );
        if !check_decomposed_bits {
            return false;
        }
        // check 2: a(u) + b(u) = c(u) + k(u) * q
        if evals.abc[0] + evals.abc[1] != evals.abc[2] + evals.k * info.q {
            return false;
        }

        // check 3: Verify the newly added part in the sumcheck polynomial
        let coin = randomness[randomness.len() - 1];
        subclaim.expected_evaluations -= coin * eq_at_u_r * evals.k * (F::one() - evals.k);
        true
    }
}

/// AdditionInZq proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct AdditionInZqProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Instance info.
    pub instance_info: AdditionInZqInstanceInfo<F>,
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
    pub evals: AdditionInZqInstanceEval<EF>,
}

impl<F, EF, S, Pcs> AdditionInZqProof<F, EF, S, Pcs>
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

/// Addition in Zq parameter.
pub struct AdditionInZqParams<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// The parameter for the polynomial commitment.
    pub pp: Pcs::Parameters,
}

impl<F, EF, S, Pcs> Default for AdditionInZqParams<F, EF, S, Pcs>
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

impl<F, EF, S, Pcs> AdditionInZqParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    pub fn setup(&mut self, instance: &AdditionInZqInstance<F>, code_spec: S) {
        self.pp = Pcs::setup(instance.generate_num_var(), Some(code_spec.clone()));
    }
}

/// Prover for addition in Zq with PCS.
pub struct AdditionInZqProver<
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

impl<F, EF, S, Pcs> Default for AdditionInZqProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        AdditionInZqProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> AdditionInZqProver<F, EF, S, Pcs>
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
        params: &AdditionInZqParams<F, EF, S, Pcs>,
        instance: &AdditionInZqInstance<F>,
    ) -> AdditionInZqProof<F, EF, S, Pcs> {
        let instance_info = instance.info();

        trans.append_message(b"addition in Zq instance", &instance_info);

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (poly_comm, poly_comm_state) = Pcs::commit(&params.pp, &committed_poly);

        trans.append_message(b"polynomial commitment", &poly_comm);

        // Prover generates the proof.
        // Convert the orignal instance into an instance defined over EF.
        let instance_ef = instance.to_ef::<EF>();
        let instance_ef_info = instance_ef.info();
        let mut add_iop = AdditionInZqIOP::<EF>::default();

        add_iop.generate_randomness(trans, &instance_ef_info);
        let kit = add_iop.prove(trans, &instance_ef);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point = kit.randomness.clone();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combinaiton for evaluations of the oracles",
            instance.log_num_oracles(),
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

        AdditionInZqProof {
            instance_info,
            poly_info: kit.info,
            poly_comm,
            oracle_eval,
            eval_proof,
            sumcheck_proof: kit.proof,
            evals,
        }
    }
}

/// Verifier for addition in Zq with PCS.
pub struct AdditionInZqVerifier<
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

impl<F, EF, S, Pcs> Default for AdditionInZqVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        AdditionInZqVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> AdditionInZqVerifier<F, EF, S, Pcs>
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
        params: &AdditionInZqParams<F, EF, S, Pcs>,
        proof: &AdditionInZqProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"addition in Zq instance", &proof.instance_info);
        trans.append_message(b"polynomial commitment", &proof.poly_comm);

        let mut add_iop = AdditionInZqIOP::<EF>::default();

        add_iop.generate_randomness(trans, &proof.instance_info.to_ef());

        let proof_wrapper = ProofWrapper {
            claimed_sum: EF::zero(),
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };

        let (b, randomness) = add_iop.verify(
            trans,
            &proof_wrapper,
            &proof.evals,
            &proof.instance_info.to_ef(),
        );

        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let flatten_evals = proof.evals.flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combinaiton for evaluations of the oracles",
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

/// Replace naive rangecheck with lookup
impl<F: Field + Serialize> AdditionInZqPure<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>) -> Vec<F> {
        trans.get_vec_challenge(b"randomness to combine sumcheck protocols", 1)
    }

    /// return the number of coins used in this IOP
    pub fn num_coins() -> usize {
        1
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prove(instance: &AdditionInZqInstance<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let randomness = Self::sample_coins(&mut trans);
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");
        // (proof, state, poly.info())
        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum: F::zero(),
            randomness: state.randomness,
            u,
        }
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &AdditionInZqInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        // sumcheck for \sum_{x} eq(u, x) * k(x) * (1-k(x)) = 0, i.e. k(x)\in\{0,1\}^l
        let coin = randomness[randomness.len() - 1];
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
            coin,
        );
    }

    /// Verify addition in Zq
    pub fn verify(
        wrapper: &ProofWrapper<F>,
        evals: &AdditionInZqInstanceEval<F>,
        info: &AdditionInZqInstanceInfo<F>,
    ) -> bool {
        let mut trans = Transcript::new();

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        // randomness to combine sumcheck protocols
        let randomness = trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(),
        );

        let mut subclaim = MLSumcheck::verify(&mut trans, &wrapper.info, F::zero(), &wrapper.proof)
            .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);

        if !Self::verify_as_subprotocol(&randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return false;
        }

        subclaim.expected_evaluations == F::zero()
    }

    /// Verify addition in Zq
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &AdditionInZqInstanceEval<F>,
        info: &AdditionInZqInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        // check 1: Verify the range check part in the sumcheck polynomial
        let bits_evals = evals.extract_decomposed_bits();
        let check_decomposed_bits =
            <BitDecompositionIOP<F>>::verify_subclaim_without_range_check(&bits_evals, &info.bits_info);
        if !check_decomposed_bits {
            return false;
        }

        // check 2: a(u) + b(u) = c(u) + k(u) * q
        if evals.abc[0] + evals.abc[1] != evals.abc[2] + evals.k * info.q {
            return false;
        }

        // check 3: Verify the newly added part in the sumcheck polynomial
        let coin = randomness[randomness.len() - 1];
        subclaim.expected_evaluations -= coin * eq_at_u_r * evals.k * (F::one() - evals.k);
        true
    }
}

// Replcae naive rangecheck with lookup
impl<F, EF> AdditionInZqSnarksOpt<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &AdditionInZqInstance<F>, code_spec: &S, block_size: usize)
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

        let mut lookup_instance = instance_ef.extract_lookup_instance(block_size);
        let lookup_info = lookup_instance.info();
        println!("- containing {lookup_info}\n");
        // random value to initiate lookup
        let random_value =
            prover_trans.get_challenge(b"random point used to generate the second oracle");
        lookup_instance.generate_h_vec(random_value);

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let claimed_sum = EF::zero();
        let randomness = AdditionInZqPure::sample_coins(&mut prover_trans);
        AdditionInZqPure::prove_as_subprotocol(
            &randomness,
            &mut sumcheck_poly,
            &instance_ef,
            &eq_at_u,
        );

        // combine lookup sumcheck
        let mut lookup_randomness =
            LookupIOP::sample_coins(&mut prover_trans, &lookup_instance.info());
        lookup_randomness.push(random_value);
        LookupIOP::prepare_products_of_polynomial(
            &lookup_randomness,
            &mut sumcheck_poly,
            &lookup_instance,
            &eq_at_u,
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
        let evals = instance.evaluate_ext(&sumcheck_state.randomness);
        let lookup_evals = lookup_instance.evaluate(&sumcheck_state.randomness);

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

        let random_value =
            verifier_trans.get_challenge(b"random point used to generate the second oracle");

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <AdditionInZqPure<EF>>::num_coins(),
        );

        let mut lookup_randomness = verifier_trans.get_vec_challenge(
            b"Lookup IOP: randomness to combine sumcheck protocols",
            <LookupIOP<EF>>::num_coins(&lookup_info),
        );
        lookup_randomness.push(random_value);

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the sumcheck proof generated in Addition in Zq");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subcliam = AdditionInZqPure::<EF>::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &evals,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subcliam);
        let check_lookup = LookupIOP::<EF>::verify_subclaim(
            &lookup_randomness,
            &mut subclaim,
            &lookup_evals,
            &lookup_info,
            eq_at_u_r,
        );
        assert!(check_lookup);
        assert!(subclaim.expected_evaluations == EF::zero());
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
        );
    }
}

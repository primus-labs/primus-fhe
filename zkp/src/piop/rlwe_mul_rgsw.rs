//! PIOP for multiplication between RLWE ciphertext and RGSW ciphertext
//! The prover wants to convince verifier the correctness of the multiplication between the RLWE ciphertext and the RGSW ciphetext
//!
//! Input: (a, b) is a RLWE ciphertext and (c, f) is a RGSW ciphertext where RLWE' = Vec<RLWE> and RGSW = RLWE' \times RLWE'.
//! Output: (g, h) is a RLWE ciphertext
//!
//! Given (a, b) \in RLWE where a and b are two polynomials represented by N coefficients,
//! and (c, f) \in RGSW = RLWE' \times RLWE' = (RLWE, ..., RLWE) \times (RLWE, ..., RLWE) where c = ((c0, c0'), ..., (ck-1, ck-1')) and f = ((f0, f0'), ..., (fk-1, fk-1'))
//! Note that (c, f) is given in the NTT form.
//!
//! The multiplication between RLWE and RGSW is performed as follows:
//! 1. Decompose the coefficients of the input RLWE into k bits: a -> (a_0, ..., a_k-1) and b -> (b_0, ..., b_k-1).
//!    Note that these are polynomials in the FHE context but oracles in the ZKP context.
//!    This can be proven with our Bit Decomposition IOP.
//! 2. Perform NTT on these bits:
//!     There are 2k NTT instance, including a_0 =NTT-equal= a_0', ..., a_k-1 =NTT-equal= a_k-1', ...,b_0 =NTT-equal= b_0', ..., b_k-1 =NTT-equal= b_k-1'
//!     NTT instance is linear, allowing us to randomize these NTT instances to obtain a single NTT instance.
//!     This can be proven with our NTT IOP.
//! 3. Compute:
//!     g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
//!     h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
//!     Each can be proven with a sumcheck protocol.
//! 4. Perform NTT on g' and h' to obtain its coefficient form g and h.
//!
//! Hence, there are 2k + 2 NTT instances in this single multiplication instance. We can randomize all these 2k+2 NTT instances to obtain a single NTT instance,
//! and use our NTT IOP to prove this randomized NTT instance.
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::MLSumcheck;
use crate::sumcheck::Proof;
use crate::utils::{eval_identity_function, gen_identity_evaluations};
use std::marker::PhantomData;
use std::rc::Rc;
use std::vec;

use algebra::utils::Transcript;
use algebra::{
    DenseMultilinearExtension, Field, FieldUniformSampler, ListOfProductsOfPolynomials,
    MultilinearExtension, PolynomialInfo,
};
use itertools::izip;
use rand_distr::Distribution;
use serde::Serialize;

use super::bit_decomposition::{BitDecomposition, BitDecompositionProof, BitDecompositionSubClaim};
use super::ntt::{NTTProof, NTTSubclaim};
use super::{DecomposedBits, DecomposedBitsInfo, NTTInstance, NTTInstanceInfo, NTTIOP};
/// SNARKs for Mutliplication between RLWE ciphertext and RGSW ciphertext
pub struct RlweMultRgswIOP<F: Field>(PhantomData<F>);

/// proof generated by prover
pub struct RlweMultRgswProof<F: Field> {
    /// proof for bit decompostion
    pub bit_decomposition_proof: BitDecompositionProof<F>,
    /// proof for ntt
    pub ntt_proof: NTTProof<F>,
    /// proof for sumcheck
    pub sumcheck_msg: Proof<F>,
}

/// subclaim reutrned to verifier
pub struct RlweMultRgswSubclaim<F: Field> {
    /// subclaim returned from the Bit Decomposition IOP
    pub bit_decomposition_subclaim: BitDecompositionSubClaim<F>,
    /// randomness used to randomize 2k + 2 ntt instances
    pub randomness_ntt: Vec<F>,
    /// subclaim returned from the NTT IOP
    pub ntt_subclaim: NTTSubclaim<F>,
    /// randomness used in combination of the two sumcheck protocol
    pub randomness_sumcheck: Vec<F>,
    /// subclaim returned from the sumcheck protocol
    pub sumcheck_subclaim: SubClaim<F>,
}

/// RLWE ciphertext (a, b) where a and b represents two polynomials in some defined polynomial ring.
/// Note that it can represent either a coefficient-form or a NTT-form.
#[derive(Clone)]
pub struct RlweCiphertext<F: Field> {
    /// the first part of the ciphertext, chosen at random in the FHE scheme.
    pub a: Rc<DenseMultilinearExtension<F>>,
    /// the second part of the ciphertext, computed with the plaintext in the FHE scheme.
    pub b: Rc<DenseMultilinearExtension<F>>,
}

/// RLWE' ciphertexts represented by two vectors, containing k RLWE ciphertext.
#[derive(Clone)]
pub struct RlweCiphertexts<F: Field> {
    /// store the first part of each RLWE ciphertext.
    pub a_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// store the second part of each RLWE ciphertext.
    pub b_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
}

impl<F: Field> RlweCiphertexts<F> {
    /// Construct an empty rlweciphertexts
    pub fn new(bits_len: usize) -> Self {
        Self {
            a_bits: Vec::with_capacity(bits_len),
            b_bits: Vec::with_capacity(bits_len),
        }
    }

    /// Add a RLWE ciphertext
    pub fn add_rlwe(&mut self, a: DenseMultilinearExtension<F>, b: DenseMultilinearExtension<F>) {
        self.a_bits.push(Rc::new(a));
        self.b_bits.push(Rc::new(b));
    }
}

/// Stores the multiplicaton instance between RLWE ciphertext and RGSW ciphertext with the corresponding NTT table
/// Given (a, b) \in RLWE where a and b are two polynomials represented by N coefficients,
/// and (c, f) \in RGSW = RLWE' \times RLWE' = (RLWE, ..., RLWE) \times (RLWE, ..., RLWE) where c = ((c0, c0'), ..., (ck-1, ck-1')) and f = ((f0, f0'), ..., (fk-1, fk-1'))
pub struct RlweMultRgswInstance<F: Field> {
    /// randomized ntt instance to be proved
    pub ntt_instance: NTTInstance<F>,
    /// info of decomposed bits
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
    /// rlwe = (a, b): store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    pub input_rlwe: RlweCiphertext<F>,
    /// bits_rlwe = (a_bits, b_bits): a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    pub bits_rlwe: RlweCiphertexts<F>,
    /// bits_rlwe_ntt: ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlweCiphertexts<F>,
    /// bits_rgsw_c_ntt: the ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlweCiphertexts<F>,
    /// bits_rgsw_c_ntt: the ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlweCiphertexts<F>,
    /// output_rlwe_ntt: store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweCiphertext<F>,
    /// output_rlwe: store the output ciphertext (g, h) in the coefficient-form
    pub output_rlwe: RlweCiphertext<F>,
}

/// store the information used to verify
#[derive(Clone, Serialize)]
pub struct RlweMultRgswInfo<F: Field> {
    /// information of ntt instance
    pub ntt_info: NTTInstanceInfo<F>,
    /// information of bit decomposition
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
}

impl<F: Field> RlweMultRgswInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> RlweMultRgswInfo<F> {
        RlweMultRgswInfo {
            ntt_info: self.ntt_instance.info(),
            decomposed_bits_info: self.decomposed_bits_info.clone(),
        }
    }

    /// Construct the instance from reference
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn from(
        decomposed_bits_info: &DecomposedBitsInfo<F>,
        ntt_info: &NTTInstanceInfo<F>,
        randomness_ntt: &[F],
        input_rlwe: &RlweCiphertext<F>,
        bits_rlwe: &RlweCiphertexts<F>,
        bits_rlwe_ntt: &RlweCiphertexts<F>,
        bits_rgsw_c_ntt: &RlweCiphertexts<F>,
        bits_rgsw_f_ntt: &RlweCiphertexts<F>,
        output_rlwe_ntt: &RlweCiphertext<F>,
        output_rlwe: &RlweCiphertext<F>,
    ) -> Self {
        let num_ntt_instance = (decomposed_bits_info.bits_len << 1) + 2;
        assert_eq!(randomness_ntt.len(), num_ntt_instance as usize);

        // randomize 2k + 1 ntt instances into a single one ntt instance
        let mut ntt_instance = NTTInstance::from_info(ntt_info);
        let mut r_iter = randomness_ntt.iter();

        // k ntt instances for a_i =NTT equal= a_i'
        for (coeffs, points) in izip!(&bits_rlwe.a_bits, &bits_rlwe_ntt.a_bits) {
            let r = *r_iter.next().unwrap();
            ntt_instance.add_ntt(r, coeffs, points);
        }
        // k ntt instances for b_i =NTT equal= b_i'
        for (coeffs, points) in izip!(&bits_rlwe.b_bits, &bits_rlwe_ntt.b_bits) {
            let r = *r_iter.next().unwrap();
            ntt_instance.add_ntt(r, coeffs, points);
        }
        // 1 ntt instances for g =NTT equal= g'
        let r = *r_iter.next().unwrap();
        ntt_instance.add_ntt(r, &output_rlwe.a, &output_rlwe_ntt.a);

        // 1 ntt instances for h =NTT equal= h'
        let r = *r_iter.next().unwrap();
        ntt_instance.add_ntt(r, &output_rlwe.b, &output_rlwe_ntt.b);

        RlweMultRgswInstance {
            ntt_instance,
            decomposed_bits_info: decomposed_bits_info.clone(),
            input_rlwe: input_rlwe.clone(),
            bits_rlwe: bits_rlwe.clone(),
            bits_rlwe_ntt: bits_rlwe_ntt.clone(),
            bits_rgsw_c_ntt: bits_rgsw_c_ntt.clone(),
            bits_rgsw_f_ntt: bits_rgsw_f_ntt.clone(),
            output_rlwe_ntt: output_rlwe_ntt.clone(),
            output_rlwe: output_rlwe.clone(),
        }
    }
}

impl<F: Field> RlweMultRgswSubclaim<F> {
    /// verify the subclaim
    ///
    /// # Arguments
    /// * `u`: random point choosen by verifier
    /// * `randomness_ntt`: randomness used for combining a batch of ntt instances into a single one
    /// * `ntt_coeffs`: coefficient form of the randomized ntt instance
    /// * `ntt_points`: point-value form of the randomized ntt instance
    /// * `input_rlwe`: rlwe = (a, b) storing the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    /// * `bits_rlwe`: bits_rlwe = (a_bits, b_bits) where a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    /// * `bits_rlwe_ntt`: ntt form of the above bit decomposition result
    /// * `bits_rgsw_c_ntt`: the ntt form of the first part (c) in the RGSW ciphertext
    /// * `bits_rgsw_f_ntt`: the ntt form of the second part (f) in the RGSW ciphertext
    /// * `output_rlwe_ntt`: store the output ciphertext (g', h') in the NTT-form
    /// * `output_rlwe`: store the output ciphertext (g, h) in the coefficient-form
    /// * `info`: contains the info for verifying ntt and bit decomposition
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim(
        &self,
        u: &[F],
        randomness_ntt: &[F],
        ntt_coeffs: &DenseMultilinearExtension<F>,
        ntt_points: &DenseMultilinearExtension<F>,
        input_rlwe: &RlweCiphertext<F>,
        bits_rlwe: &RlweCiphertexts<F>,
        bits_rlwe_ntt: &RlweCiphertexts<F>,
        bits_rgsw_c_ntt: &RlweCiphertexts<F>,
        bits_rgsw_f_ntt: &RlweCiphertexts<F>,
        output_rlwe_ntt: &RlweCiphertext<F>,
        output_rlwe: &RlweCiphertext<F>,
        info: &RlweMultRgswInfo<F>,
    ) -> bool {
        let num_ntt_instance = (info.decomposed_bits_info.bits_len << 1) + 2;
        assert_eq!(randomness_ntt.len(), num_ntt_instance as usize);
        assert_eq!(u.len(), info.ntt_info.log_n);
        assert_eq!(self.randomness_sumcheck.len(), 2);

        // check 1: check the consistency of the randomized ntt oracle and the original oracles
        let mut coeffs_eval = F::zero();
        let mut points_eval = F::zero();
        let mut r_iter = randomness_ntt.iter();

        for (coeffs, points) in izip!(&bits_rlwe.a_bits, &bits_rlwe_ntt.a_bits) {
            let r = r_iter.next().unwrap();
            coeffs_eval += *r * coeffs.evaluate(u);
            points_eval += *r * points.evaluate(u);
        }
        for (coeffs, points) in izip!(&bits_rlwe.b_bits, &bits_rlwe_ntt.b_bits) {
            let r = r_iter.next().unwrap();
            coeffs_eval += *r * coeffs.evaluate(u);
            points_eval += *r * points.evaluate(u);
        }
        let r = r_iter.next().unwrap();
        coeffs_eval += *r * output_rlwe.a.evaluate(u);
        points_eval += *r * output_rlwe_ntt.a.evaluate(u);
        let r = r_iter.next().unwrap();
        coeffs_eval += *r * output_rlwe.b.evaluate(u);
        points_eval += *r * output_rlwe_ntt.b.evaluate(u);

        if coeffs_eval != ntt_coeffs.evaluate(u) || points_eval != ntt_points.evaluate(u) {
            return false;
        }

        // TODO: For ease of implementation, we pass the resulting randomized ntt_instance but it can be omitted after combined with PCS.
        // check 2: check the subclaim returned from the ntt iop
        if !self
            .ntt_subclaim
            .verify_subcliam(ntt_points, ntt_coeffs, u, &info.ntt_info)
        {
            return false;
        }

        // check 3: check the subclaim returned from the bit decomposition iop
        let d_bits = vec![&bits_rlwe.a_bits, &bits_rlwe.b_bits];
        let d_val = vec![input_rlwe.a.clone(), input_rlwe.b.clone()];
        if !self.bit_decomposition_subclaim.verify_subclaim(
            &d_val,
            &d_bits,
            u,
            &info.decomposed_bits_info,
        ) {
            return false;
        }

        // 4. check 4: check the subclaim returned from the sumcheck protocol consisting of two sub-sumcheck protocols
        let mut sum1_eval = F::zero();
        let mut sum2_eval = F::zero();

        // The first part is to evaluate at a random point g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
        // It is the reduction claim of prover asserting the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
        // where u is randomly sampled by the verifier.
        for (a, b, c, f) in izip!(
            &bits_rlwe_ntt.a_bits,
            &bits_rlwe_ntt.b_bits,
            &bits_rgsw_c_ntt.a_bits,
            &bits_rgsw_f_ntt.a_bits
        ) {
            sum1_eval += (a.evaluate(&self.sumcheck_subclaim.point)
                * c.evaluate(&self.sumcheck_subclaim.point))
                + (b.evaluate(&self.sumcheck_subclaim.point)
                    * f.evaluate(&self.sumcheck_subclaim.point));
        }

        // The second part is to evaluate at a random point h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
        // It is the reduction claim of prover asserting the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i'(x) + b_i'(x) \cdot f_i'(x) - g'(x)) = 0
        // where u is randomly sampled by the verifier.
        for (a, b, c, f) in izip!(
            &bits_rlwe_ntt.a_bits,
            &bits_rlwe_ntt.b_bits,
            &bits_rgsw_c_ntt.b_bits,
            &bits_rgsw_f_ntt.b_bits
        ) {
            sum2_eval += (a.evaluate(&self.sumcheck_subclaim.point)
                * c.evaluate(&self.sumcheck_subclaim.point))
                + (b.evaluate(&self.sumcheck_subclaim.point)
                    * f.evaluate(&self.sumcheck_subclaim.point));
        }

        self.sumcheck_subclaim.expected_evaluations
            == eval_identity_function(u, &self.sumcheck_subclaim.point)
                * (self.randomness_sumcheck[0]
                    * (sum1_eval - output_rlwe_ntt.a.evaluate(&self.sumcheck_subclaim.point))
                    + self.randomness_sumcheck[1]
                        * (sum2_eval - output_rlwe_ntt.b.evaluate(&self.sumcheck_subclaim.point)))
    }
}

impl<F: Field> RlweMultRgswIOP<F> {
    /// prove the multiplication between RLWE ciphertext and RGSW ciphertext
    pub fn prove(instance: &RlweMultRgswInstance<F>, u: &[F]) -> RlweMultRgswProof<F> {
        let mut trans = Transcript::<F>::new();
        Self::prove_as_subprotocol(&mut trans, instance, u)
    }

    /// prove the multiplication between RLWE ciphertext and RGSW ciphertext
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        trans: &mut Transcript<F>,
        instance: &RlweMultRgswInstance<F>,
        u: &[F],
    ) -> RlweMultRgswProof<F> {
        // construct the instance of bit decomposition
        let mut decomposed_bits = DecomposedBits::from_info(&instance.decomposed_bits_info);
        decomposed_bits.add_decomposed_bits_instance(&instance.bits_rlwe.a_bits);
        decomposed_bits.add_decomposed_bits_instance(&instance.bits_rlwe.b_bits);

        let uniform = <FieldUniformSampler<F>>::new();

        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.ntt_instance.log_n);
        let identity_func_at_u = Rc::new(gen_identity_evaluations(u));

        // randomly combine two sumcheck protocols
        let mut fs_rng = trans.rng(b"rlwe mul rgsw");
        let r_1 = uniform.sample(&mut fs_rng);
        let r_2 = uniform.sample(&mut fs_rng);
        // Sumcheck protocol for proving: g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
        // When proving g'(x) = \sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) for x \in \{0, 1\}^\log n,
        // prover claims the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
        // where u is randomly sampled by the verifier.
        for (a, b, c, f) in izip!(
            &instance.bits_rlwe_ntt.a_bits,
            &instance.bits_rlwe_ntt.b_bits,
            &instance.bits_rgsw_c_ntt.a_bits,
            &instance.bits_rgsw_f_ntt.a_bits
        ) {
            let prod1 = [Rc::clone(a), Rc::clone(c), Rc::clone(&identity_func_at_u)];
            let prod2 = [Rc::clone(b), Rc::clone(f), Rc::clone(&identity_func_at_u)];
            poly.add_product(prod1, r_1);
            poly.add_product(prod2, r_1);
        }

        // Sumcheck protocol for proving: h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
        for (a, b, c, f) in izip!(
            &instance.bits_rlwe_ntt.a_bits,
            &instance.bits_rlwe_ntt.b_bits,
            &instance.bits_rgsw_c_ntt.b_bits,
            &instance.bits_rgsw_f_ntt.b_bits
        ) {
            let prod1 = [Rc::clone(a), Rc::clone(c), Rc::clone(&identity_func_at_u)];
            let prod2 = [Rc::clone(b), Rc::clone(f), Rc::clone(&identity_func_at_u)];
            poly.add_product(prod1, r_2);
            poly.add_product(prod2, r_2);
        }

        poly.add_product(
            [
                Rc::clone(&instance.output_rlwe_ntt.a),
                Rc::clone(&identity_func_at_u),
            ],
            -r_1,
        );
        poly.add_product(
            [
                Rc::clone(&instance.output_rlwe_ntt.b),
                Rc::clone(&identity_func_at_u),
            ],
            -r_2,
        );

        RlweMultRgswProof {
            bit_decomposition_proof: BitDecomposition::prove_as_subprotocol(
                trans,
                &decomposed_bits,
                u,
            ),
            ntt_proof: NTTIOP::prove_as_subprotocol(trans, &instance.ntt_instance, u),
            sumcheck_msg: MLSumcheck::prove_as_subprotocol(trans, &poly)
                .expect("sumcheck fail in rlwe * rgsw")
                .0,
        }
    }

    /// verify the proof
    pub fn verify(
        proof: &RlweMultRgswProof<F>,
        randomness_ntt: &[F],
        u: &[F],
        info: &RlweMultRgswInfo<F>,
    ) -> RlweMultRgswSubclaim<F> {
        let mut trans = Transcript::<F>::new();
        Self::verify_as_subprotocol(&mut trans, proof, randomness_ntt, u, info)
    }

    /// verify the proof with provided RNG
    pub fn verify_as_subprotocol(
        trans: &mut Transcript<F>,
        proof: &RlweMultRgswProof<F>,
        randomness_ntt: &[F],
        u: &[F],
        info: &RlweMultRgswInfo<F>,
    ) -> RlweMultRgswSubclaim<F> {
        let uniform = <FieldUniformSampler<F>>::new();
        let mut fs_rng = trans.rng(b"rlwe mul rgsw");
        let r_1 = uniform.sample(&mut fs_rng);
        let r_2 = uniform.sample(&mut fs_rng);
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: info.ntt_info.log_n,
        };

        RlweMultRgswSubclaim {
            bit_decomposition_subclaim: BitDecomposition::verifier_as_subprotocol(
                trans,
                &proof.bit_decomposition_proof,
                &info.decomposed_bits_info,
            ),
            ntt_subclaim: NTTIOP::verify_as_subprotocol(trans, &proof.ntt_proof, &info.ntt_info, u),
            randomness_ntt: randomness_ntt.to_owned(),
            randomness_sumcheck: vec![r_1, r_2],
            sumcheck_subclaim: MLSumcheck::verify_as_subprotocol(
                trans,
                &poly_info,
                F::zero(),
                &proof.sumcheck_msg,
            )
            .expect("sumcheck protocol in rlwe mult rgsw failed"),
        }
    }
}

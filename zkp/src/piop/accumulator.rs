//! IOP for Accumulator updating t times
//! ACC = ACC + (X^{-a_u} - 1) * ACC * RGSW(Z_u)
//! Each updation contains two single ntt operations and one multiplication between RLWE and RGSW
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::MLSumcheck;
use crate::sumcheck::Proof;
use crate::utils::eval_identity_function;
use std::marker::PhantomData;
use std::rc::Rc;

use algebra::utils::Transcript;
use algebra::AbstractExtensionField;
use algebra::DenseMultilinearExtensionBase;
use algebra::{
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension,
    PolynomialInfo,
};
use itertools::izip;
use serde::Serialize;

use super::bit_decomposition::{BitDecomposition, BitDecompositionProof, BitDecompositionSubClaim};
use super::ntt::NTTInstanceExt;
use super::ntt::{NTTProof, NTTSubclaim};
use super::rlwe_mul_rgsw::RlweCiphertextExt;
use super::rlwe_mul_rgsw::RlweCiphertextsExt;
use super::{DecomposedBits, DecomposedBitsInfo, NTTInstanceInfo, NTTIOP};
use super::{RlweCiphertext, RlweCiphertexts};

/// SNARKs for Mutliplication between RLWE ciphertext and RGSW ciphertext
pub struct AccumulatorIOP<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

/// proof generated by prover
pub struct AccumulatorProof<F: Field, EF: AbstractExtensionField<F>> {
    /// proof for bit decompostion
    pub bit_decomposition_proof: BitDecompositionProof<F, EF>,
    /// proof for ntt
    pub ntt_proof: NTTProof<F, EF>,
    /// proof for sumcheck
    pub sumcheck_msg: Proof<F, EF>,
}

/// subclaim reutrned to verifier
pub struct AccumulatorSubclaim<F: Field, EF: AbstractExtensionField<F>> {
    /// subclaim returned from the Bit Decomposition IOP
    pub bit_decomposition_subclaim: BitDecompositionSubClaim<F, EF>,
    /// subclaim returned from the NTT IOP
    pub ntt_subclaim: NTTSubclaim<F, EF>,
    /// subclaim returned from the sumcheck protocol
    pub sumcheck_subclaim: SubClaim<F, EF>,
}

/// accumulator witness when performing ACC = ACC + (X^{-a_u} + 1) * ACC * RGSW(Z_u)
pub struct AccumulatorWitness<F: Field> {
    /// * Witness when performing input_rlwe_ntt := (X^{-a_u} + 1) * ACC
    ///   accumulator of ntt form
    pub accumulator_ntt: RlweCiphertext<F>,
    /// scalar d = (X^{-a_u} + 1) of coefficient form
    pub d: Rc<DenseMultilinearExtensionBase<F>>,
    /// scalar d = (X^{-a_u} + 1) of ntt form
    pub d_ntt: Rc<DenseMultilinearExtensionBase<F>>,
    /// result d * ACC of ntt form
    pub input_rlwe_ntt: RlweCiphertext<F>,
    /// * Witness when performing output_rlwe_ntt := input_rlwe * RGSW(Z_u) where input_rlwe = (X^{-a_u} + 1) * ACC
    ///   result d * ACC of coefficient form
    ///   rlwe = (a, b): store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
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
}

/// Store the corresponding MLE of AccumulatorWitness where the evaluations are over the extension field.
pub struct AccumulatorWitnessExt<F: Field, EF: AbstractExtensionField<F>> {
    /// bits_rlwe_ntt: ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlweCiphertextsExt<F, EF>,
    /// bits_rgsw_c_ntt: the ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlweCiphertextsExt<F, EF>,
    /// bits_rgsw_c_ntt: the ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlweCiphertextsExt<F, EF>,
    /// output_rlwe_ntt: store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweCiphertextExt<F, EF>,
}

impl<F: Field, EF: AbstractExtensionField<F>> AccumulatorWitnessExt<F, EF> {
    /// Construct an instance over the extension field from the original instance defined over the basic field
    pub fn from_base(input_base: &AccumulatorWitness<F>) -> Self {
        Self {
            bits_rlwe_ntt: <RlweCiphertextsExt<F, EF>>::from_base(&input_base.bits_rlwe_ntt),
            bits_rgsw_c_ntt: <RlweCiphertextsExt<F, EF>>::from_base(&input_base.bits_rgsw_c_ntt),
            bits_rgsw_f_ntt: <RlweCiphertextsExt<F, EF>>::from_base(&input_base.bits_rgsw_f_ntt),
            output_rlwe_ntt: <RlweCiphertextExt<F, EF>>::from_base(&input_base.output_rlwe_ntt),
        }
    }
}

/// Store the ntt instance, bit decomposition instance, and the sumcheck instance for an Accumulator upating t times
pub struct AccumulatorInstance<F: Field, EF: AbstractExtensionField<F>> {
    /// number of updations in Accumulator denoted by t
    pub num_updations: usize,
    /// number of ntt transformation in Accumulator
    pub num_ntt: usize,
    /// the (virtually) randomized ntt instance to be proved
    pub ntt_instance: NTTInstanceExt<F, EF>,
    /// all decomposed bits
    pub decomposed_bits: DecomposedBits<F>,
    /// poly in the sumcheck instance
    pub poly: ListOfProductsOfPolynomials<F, EF>,
}

/// Store the Accumulator info used to verify
#[derive(Serialize)]
pub struct AccumulatorInstanceInfo<F: Field> {
    /// number of updations in Accumulator denoted by t
    pub num_updations: usize,
    /// info to verify ntt
    pub ntt_info: NTTInstanceInfo<F>,
    /// info to verify bit decomposition
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
    /// info to verify sumcheck
    pub poly_info: PolynomialInfo,
}

impl<F: Field, EF: AbstractExtensionField<F>> AccumulatorInstance<F, EF> {
    /// construct an accumulator instance based on ntt info and bit-decomposition info
    #[inline]
    pub fn new(
        num_vars: usize,
        ntt_info: &NTTInstanceInfo<F>,
        decom_info: &DecomposedBitsInfo<F>,
    ) -> Self {
        Self {
            num_updations: 0,
            num_ntt: 0,
            ntt_instance: <NTTInstanceExt<F, EF>>::from_info(ntt_info),
            decomposed_bits: <DecomposedBits<F>>::from_info(decom_info),
            poly: <ListOfProductsOfPolynomials<F, EF>>::new(num_vars),
        }
    }

    /// Extract the information
    #[inline]
    pub fn info(&self) -> AccumulatorInstanceInfo<F> {
        AccumulatorInstanceInfo {
            num_updations: self.num_updations,
            ntt_info: self.ntt_instance.info(),
            decomposed_bits_info: self.decomposed_bits.info(),
            poly_info: self.poly.info(),
        }
    }

    /// add witness
    ///
    /// # Arguments:
    /// * randomness_ntt: randomness used for integrating (2k+3) ntt instances into the target ntt instance
    /// * randomness_sumcheck: randomness used to integrating 2 sumcheck protocols
    /// * identity_func_at_u: identity function at the random point u where u is chosen for sumcheck protocol
    /// * witness: all intermediate witness when updating the accumulator once
    pub fn add_witness(
        &mut self,
        randomness_ntt: &[EF],
        randomness_sumcheck: &[EF],
        identity_func_at_u: &Rc<DenseMultilinearExtension<F, EF>>,
        witness: &AccumulatorWitness<F>,
    ) {
        self.num_updations += 1;
        assert_eq!(
            randomness_ntt.len(),
            ((self.decomposed_bits.bits_len << 1) + 3) as usize
        );
        self.num_ntt += randomness_ntt.len();
        assert_eq!(randomness_sumcheck.len(), 2);

        // Integrate the Bit-Decomposition Part
        assert_eq!(
            witness.bits_rlwe.a_bits.len(),
            self.decomposed_bits.bits_len as usize
        );
        assert_eq!(
            witness.bits_rlwe.b_bits.len(),
            self.decomposed_bits.bits_len as usize
        );
        self.decomposed_bits
            .add_decomposed_bits_instance(&witness.bits_rlwe.a_bits);
        self.decomposed_bits
            .add_decomposed_bits_instance(&witness.bits_rlwe.b_bits);

        // Integrate the NTT Part
        let mut r = randomness_ntt.iter();
        self.ntt_instance
            .add_ntt(*r.next().unwrap(), &witness.d, &witness.d_ntt);
        self.ntt_instance.add_ntt(
            *r.next().unwrap(),
            &witness.input_rlwe.a,
            &witness.input_rlwe_ntt.a,
        );
        self.ntt_instance.add_ntt(
            *r.next().unwrap(),
            &witness.input_rlwe.b,
            &witness.input_rlwe_ntt.b,
        );

        // k ntt instances for a_i =NTT equal= a_i'
        for (coeffs, points) in izip!(&witness.bits_rlwe.a_bits, &witness.bits_rlwe_ntt.a_bits) {
            self.ntt_instance
                .add_ntt(*r.next().unwrap(), coeffs, points);
        }
        // k ntt instances for b_i =NTT equal= b_i'
        for (coeffs, points) in izip!(&witness.bits_rlwe.b_bits, &witness.bits_rlwe_ntt.b_bits) {
            self.ntt_instance
                .add_ntt(*r.next().unwrap(), coeffs, points);
        }

        // Convert the original instance to a new instance over the extension field
        let witness = <AccumulatorWitnessExt<F, EF>>::from_base(witness);

        // Integrate the Sumcheck Part
        let r_1 = randomness_sumcheck[0];
        let r_2 = randomness_sumcheck[1];
        // Sumcheck protocol for proving: g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
        // When proving g'(x) = \sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) for x \in \{0, 1\}^\log n,
        // prover claims the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
        // where u is randomly sampled by the verifier.
        for (a, b, c, f) in izip!(
            &witness.bits_rlwe_ntt.a_bits,
            &witness.bits_rlwe_ntt.b_bits,
            &witness.bits_rgsw_c_ntt.a_bits,
            &witness.bits_rgsw_f_ntt.a_bits
        ) {
            let prod1 = [Rc::clone(a), Rc::clone(c), Rc::clone(identity_func_at_u)];
            let prod2 = [Rc::clone(b), Rc::clone(f), Rc::clone(identity_func_at_u)];
            self.poly.add_product(prod1, r_1);
            self.poly.add_product(prod2, r_1);
        }
        // Sumcheck protocol for proving: h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
        for (a, b, c, f) in izip!(
            &witness.bits_rlwe_ntt.a_bits,
            &witness.bits_rlwe_ntt.b_bits,
            &witness.bits_rgsw_c_ntt.b_bits,
            &witness.bits_rgsw_f_ntt.b_bits
        ) {
            let prod1 = [Rc::clone(a), Rc::clone(c), Rc::clone(identity_func_at_u)];
            let prod2 = [Rc::clone(b), Rc::clone(f), Rc::clone(identity_func_at_u)];
            self.poly.add_product(prod1, r_2);
            self.poly.add_product(prod2, r_2);
        }

        self.poly.add_product(
            [
                Rc::clone(&witness.output_rlwe_ntt.a),
                Rc::clone(identity_func_at_u),
            ],
            -r_1,
        );
        self.poly.add_product(
            [
                Rc::clone(&witness.output_rlwe_ntt.b),
                Rc::clone(identity_func_at_u),
            ],
            -r_2,
        );
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> AccumulatorIOP<F, EF> {
    /// prove the accumulator updation
    pub fn prove(
        trans: &mut Transcript<F>,
        instance: &AccumulatorInstance<F, EF>,
        u: &[EF],
    ) -> AccumulatorProof<F, EF> {
        AccumulatorProof {
            bit_decomposition_proof: BitDecomposition::prove(trans, &instance.decomposed_bits, u),
            ntt_proof: NTTIOP::prove(trans, &instance.ntt_instance, u),
            sumcheck_msg: MLSumcheck::prove(trans, &instance.poly)
                .expect("sumcheck fail in accumulator updation")
                .0,
        }
    }

    /// verify the proof
    pub fn verify(
        trans: &mut Transcript<F>,
        proof: &AccumulatorProof<F, EF>,
        u: &[EF],
        info: &AccumulatorInstanceInfo<F>,
    ) -> AccumulatorSubclaim<F, EF> {
        AccumulatorSubclaim {
            bit_decomposition_subclaim: BitDecomposition::verify(
                trans,
                &proof.bit_decomposition_proof,
                &info.decomposed_bits_info,
            ),
            ntt_subclaim: NTTIOP::verify(trans, &proof.ntt_proof, &info.ntt_info, u),
            sumcheck_subclaim: MLSumcheck::verify(
                trans,
                &info.poly_info,
                EF::zero(),
                &proof.sumcheck_msg,
            )
            .expect("sumcheck protocol in rlwe mult rgsw failed"),
        }
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> AccumulatorSubclaim<F, EF> {
    /// verify the subclaim
    ///
    /// # Arguments
    /// * u: random point chosen by verifier
    /// * randomness_ntt: randomness used to combine ntt instances
    /// * randomness_sumecheck: randomness used to combine sumcheck protocols
    /// * ntt_coeffs: the final random ntt instance to be proved
    /// * ntt_points: the final random ntt instance to be proved
    /// * witness: all the winess when updating the accumulator
    /// * info: info used to verify
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim(
        &self,
        u: &[EF],
        randomness_ntt: &[EF],
        randomness_sumcheck: &[EF],
        ntt_coeffs: &DenseMultilinearExtension<F, EF>,
        ntt_points: &DenseMultilinearExtension<F, EF>,
        witnesses: &Vec<AccumulatorWitness<F>>,
        info: &AccumulatorInstanceInfo<F>,
    ) -> bool {
        let num_ntt_instance =
            (info.num_updations as u32) * ((info.decomposed_bits_info.bits_len << 1) + 3);
        assert_eq!(randomness_ntt.len(), num_ntt_instance as usize);
        assert_eq!(u.len(), info.ntt_info.log_n);
        assert_eq!(randomness_sumcheck.len(), 2 * info.num_updations);

        // check 1: check the consistency of the randomized ntt instance and the original ntt instances
        let mut coeffs_eval = EF::zero();
        let mut points_eval = EF::zero();
        let mut r_iter = randomness_ntt.iter();

        for witness in witnesses {
            let r = r_iter.next().unwrap();
            coeffs_eval += *r * witness.d.evaluate_ext(u);
            points_eval += *r * witness.d_ntt.evaluate_ext(u);
            let r = r_iter.next().unwrap();
            coeffs_eval += *r * witness.input_rlwe.a.evaluate_ext(u);
            points_eval += *r * witness.input_rlwe_ntt.a.evaluate_ext(u);
            let r = r_iter.next().unwrap();
            coeffs_eval += *r * witness.input_rlwe.b.evaluate_ext(u);
            points_eval += *r * witness.input_rlwe_ntt.b.evaluate_ext(u);

            for (coeffs, points) in izip!(&witness.bits_rlwe.a_bits, &witness.bits_rlwe_ntt.a_bits)
            {
                let r = r_iter.next().unwrap();
                coeffs_eval += *r * coeffs.evaluate_ext(u);
                points_eval += *r * points.evaluate_ext(u);
            }

            for (coeffs, points) in izip!(&witness.bits_rlwe.b_bits, &witness.bits_rlwe_ntt.b_bits)
            {
                let r = r_iter.next().unwrap();
                coeffs_eval += *r * coeffs.evaluate_ext(u);
                points_eval += *r * points.evaluate_ext(u);
            }
        }
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
        let mut d_bits = Vec::with_capacity(2 * info.num_updations);
        let mut d_val = Vec::with_capacity(2 * info.num_updations);
        for witness in witnesses {
            d_bits.push(&witness.bits_rlwe.a_bits);
            d_bits.push(&witness.bits_rlwe.b_bits);
            d_val.push(Rc::clone(&witness.input_rlwe.a));
            d_val.push(Rc::clone(&witness.input_rlwe.b));
        }
        if !self.bit_decomposition_subclaim.verify_subclaim(
            &d_val,
            &d_bits,
            u,
            &info.decomposed_bits_info,
        ) {
            return false;
        }

        let mut r = randomness_sumcheck.iter();

        // 4. check 4: check the subclaim returned from the sumcheck protocol consisting of two sub-sumcheck protocols
        let mut sum_eval = EF::zero();
        for witness in witnesses {
            let mut sum1_eval = EF::zero();
            let mut sum2_eval = EF::zero();
            // The first part is to evaluate at a random point g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
            // It is the reduction claim of prover asserting the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
            // where u is randomly sampled by the verifier.
            for (a, b, c, f) in izip!(
                &witness.bits_rlwe_ntt.a_bits,
                &witness.bits_rlwe_ntt.b_bits,
                &witness.bits_rgsw_c_ntt.a_bits,
                &witness.bits_rgsw_f_ntt.a_bits
            ) {
                sum1_eval += (a.evaluate_ext(&self.sumcheck_subclaim.point)
                    * c.evaluate_ext(&self.sumcheck_subclaim.point))
                    + (b.evaluate_ext(&self.sumcheck_subclaim.point)
                        * f.evaluate_ext(&self.sumcheck_subclaim.point));
            }

            // The second part is to evaluate at a random point h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
            // It is the reduction claim of prover asserting the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i'(x) + b_i'(x) \cdot f_i'(x) - g'(x)) = 0
            // where u is randomly sampled by the verifier.
            for (a, b, c, f) in izip!(
                &witness.bits_rlwe_ntt.a_bits,
                &witness.bits_rlwe_ntt.b_bits,
                &witness.bits_rgsw_c_ntt.b_bits,
                &witness.bits_rgsw_f_ntt.b_bits
            ) {
                sum2_eval += (a.evaluate_ext(&self.sumcheck_subclaim.point)
                    * c.evaluate_ext(&self.sumcheck_subclaim.point))
                    + (b.evaluate_ext(&self.sumcheck_subclaim.point)
                        * f.evaluate_ext(&self.sumcheck_subclaim.point));
            }

            let r_1 = r.next().unwrap();
            let r_2 = r.next().unwrap();
            sum_eval += eval_identity_function(u, &self.sumcheck_subclaim.point)
                * (*r_1
                    * (sum1_eval
                        - witness
                            .output_rlwe_ntt
                            .a
                            .evaluate_ext(&self.sumcheck_subclaim.point))
                    + *r_2
                        * (sum2_eval
                            - witness
                                .output_rlwe_ntt
                                .b
                                .evaluate_ext(&self.sumcheck_subclaim.point)))
        }
        sum_eval == self.sumcheck_subclaim.expected_evaluations
    }
}

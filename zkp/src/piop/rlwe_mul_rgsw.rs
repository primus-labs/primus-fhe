//! PIOP for multiplication between RLWE ciphertext and RGSW ciphertext
//! The prover wants to convince the correctness of the multiplication between the RLWE ciphertext and the RGSW ciphetext
//! 
//! Input: (a, b) is a RLWE ciphertext and (c, f) is a RGSW ciphertext where RLWE' = Vec<RLWE> and RGSW = RLWE' \times RLWE'.
//! Output: (g, h) is a RLWE ciphertext
//! 
//! Given (a, b) \in RLWE where a and b are two polynomials represented by N coefficients,
//! and (c, f) \in RGSW = RLWE' \times RLWE' = (RLWE, ..., RLWE) \times (RLWE, ..., RLWE) where c = ((c0, c0'), ..., (ck-1, ck-1')) and f = ((f0, f0'), ..., (fk-1, fk-1'))
//! 
//! The multiplication between RLWE and RGSW is performed as follows:
//! 1. Decompose the coefficeints of a and b into k bits.
use std::marker::PhantomData;
use std::rc::Rc;
use crate::sumcheck::{Proof};
use crate::sumcheck::MLSumcheck;
use crate::utils::{eval_identity_function, gen_identity_evaluations};

use algebra::{
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
    FieldUniformSampler,
};
use rand_distr::Distribution;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

use super::bit_decomposition::{BitDecomposition, BitDecompositionProof, BitDecompositionSubClaim};
use super::ntt::{NTTProof, NTTSubclaim};
use super::{DecomposedBits, DecomposedBitsInfo, NTTInstance, NTTInstanceInfo, NTTIOP};
/// 
pub struct RlweMultRgswIOP<F: Field>(PhantomData<F>);

///
pub struct RlweMultRgswProof<F: Field> {
    ///
    pub bit_decomposition_proof: BitDecompositionProof<F>,
    ///
    pub ntt_proof: NTTProof<F>, 
    ///
    pub sumcheck_msg: Proof<F>,
}

/// subclaim reutrned to verifier
pub struct RlweMultRgswSubclaim<F: Field> {
    /// 
    pub bit_decomposition_subcliam: BitDecompositionSubClaim<F>,
    /// randomness used to randomize ntt_instance
    pub randomness_ntt: Vec<F>,
    /// 
    pub ntt_subclaim: NTTSubclaim<F>,
    /// randomness used in combination of sumcheck protocol
    pub randomness_sumcheck: Vec<F>,
    /// reduced point from the sumcheck protocol
    pub point: Vec<F>,
    /// expected value returned in the last round of the sumcheck protocol
    pub expected_evaluation: F,
}

/// 
#[derive(Clone)]
pub struct RlweCiphertext<F: Field> {
    ///
    pub a: Rc<DenseMultilinearExtension<F>>,
    ///
    pub b: Rc<DenseMultilinearExtension<F>>,
}

///
#[derive(Clone)]
pub struct RlweCiphertexts<F: Field> {
    /// 
    pub a_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    ///
    pub b_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
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
    /// 
    pub output_rlwe_ntt: RlweCiphertext<F>,
    /// 
    pub output_rlwe: RlweCiphertext<F>,
}

/// 
pub struct RlweMultRgswInfo<F: Field> {
    /// 
    pub ntt_info: NTTInstanceInfo<F>,
    /// 
    pub decomposed_bits_info: DecomposedBitsInfo<F>,
}

impl<F: Field> RlweMultRgswInstance<F> {
    /// 
    #[inline]
    pub fn info(&self) -> RlweMultRgswInfo<F> {
        RlweMultRgswInfo {
            ntt_info: self.ntt_instance.info(),
            decomposed_bits_info: self.decomposed_bits_info.clone(),
        }
    }

    /// Construct the instance
    #[inline]
    pub fn new(
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
        let num_vars = ntt_info.log_n;
        let num_ntt_instance = (decomposed_bits_info.bits_len << 1) + 2;
        assert_eq!(randomness_ntt.len(), num_ntt_instance as usize);

        // obtain the randomized ntt instance
        let mut ntt_coeffs = DenseMultilinearExtension::from_evaluations_vec(num_vars, vec![F::ZERO; 1 << num_vars]);
        let mut ntt_points = DenseMultilinearExtension::from_evaluations_vec(num_vars, vec![F::ZERO; 1 << num_vars]);
        let mut r_iter = randomness_ntt.iter();

        bits_rlwe.a_bits.iter().zip(bits_rlwe_ntt.a_bits.iter())
            .for_each(|(coeffs, points)| {
                let r = *r_iter.next().unwrap();
                ntt_coeffs += (r, coeffs);
                ntt_points += (r, points);
            });
        bits_rlwe.b_bits.iter().zip(bits_rlwe_ntt.b_bits.iter())
            .for_each(|(coeffs, points)| {
                let r = *r_iter.next().unwrap();
                ntt_coeffs += (r, coeffs);
                ntt_points += (r, points);
            });
        let r = *r_iter.next().unwrap();
        ntt_coeffs += (r, &output_rlwe.a);
        ntt_points += (r, &output_rlwe_ntt.a);
        let r = *r_iter.next().unwrap();
        ntt_coeffs += (r, &output_rlwe.b);
        ntt_points += (r, &output_rlwe_ntt.b);

        let ntt_instance = NTTInstance::from_slice(num_vars, &ntt_info.ntt_table, &Rc::new(ntt_coeffs), &Rc::new(ntt_points));
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

/// 
impl<F: Field> RlweMultRgswSubclaim<F> {
    /// 
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
        let mut coeffs_eval = F::ZERO;
        let mut points_eval = F::ZERO;
        let mut r_iter = randomness_ntt.iter();
        bits_rlwe.a_bits.iter().zip(bits_rlwe_ntt.a_bits.iter())
            .for_each(|(coeffs, points)| {
                let r = r_iter.next().unwrap();
                coeffs_eval += *r * coeffs.evaluate(u);
                points_eval += *r * points.evaluate(u);
            });
        bits_rlwe.b_bits.iter().zip(bits_rlwe_ntt.b_bits.iter())
            .for_each(|(coeffs, points)| {
                let r = r_iter.next().unwrap();
                coeffs_eval += *r * coeffs.evaluate(u);
                points_eval += *r * points.evaluate(u);
            });
        let r = r_iter.next().unwrap();
        coeffs_eval += *r * output_rlwe.a.evaluate(u);
        points_eval += *r * output_rlwe_ntt.a.evaluate(u);
        let r = r_iter.next().unwrap();
        coeffs_eval += *r * output_rlwe.b.evaluate(u);
        points_eval += *r * output_rlwe_ntt.b.evaluate(u);
        
        if coeffs_eval != ntt_coeffs.evaluate(u) || points_eval != ntt_points.evaluate(u) {
            return false;
        }

        // check 2: check the subclaim returned from the ntt iop
        if !self.ntt_subclaim.verify_subcliam(ntt_points, ntt_coeffs, u, &info.ntt_info) {
            return false;
        }

        // check 3: check the subclaim returned from the bit decomposition iop
        let d_bits = vec![
            &bits_rlwe.a_bits,
            &bits_rlwe.a_bits,
        ];
        let d_val = vec![
            input_rlwe.a.clone(),
            input_rlwe.b.clone(),
        ];
        if !self.bit_decomposition_subcliam.verify_subclaim(&d_val, &d_bits, u, &info.decomposed_bits_info) {
            return false;
        }

        let mut sum1_eval = F::ZERO;
        let mut sum2_eval = F::ZERO;
        bits_rlwe_ntt.a_bits.iter().zip(bits_rlwe_ntt.b_bits.iter())
            .zip(bits_rgsw_c_ntt.a_bits.iter()).zip(bits_rgsw_f_ntt.a_bits.iter())
            .for_each(|(((a, b), c), f)| {
                sum1_eval += a.evaluate(&self.point) * c.evaluate(&self.point) + b.evaluate(&self.point) * f.evaluate(&self.point);
            });
        bits_rlwe_ntt.a_bits.iter().zip(bits_rlwe_ntt.b_bits.iter())
            .zip(bits_rgsw_c_ntt.b_bits.iter()).zip(bits_rgsw_f_ntt.b_bits.iter())
            .for_each(|(((a, b), c), f)| {
                sum2_eval += a.evaluate(&self.point) * c.evaluate(&self.point) + b.evaluate(&self.point) * f.evaluate(&self.point);
            });
        self.expected_evaluation == (self.randomness_sumcheck[0] * (sum1_eval - output_rlwe_ntt.a.evaluate(&self.point)) 
            + self.randomness_sumcheck[1] * (sum2_eval - output_rlwe_ntt.b.evaluate(&self.point))) * eval_identity_function(u, &self.point)
    }
}

///
impl<F: Field> RlweMultRgswIOP<F> {
    ///
    pub fn prove(
        instance: &RlweMultRgswInstance<F>,
        u: &[F],
    )-> RlweMultRgswProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, instance, u)
    }

    ///
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        instance: &RlweMultRgswInstance<F>,
        u: &[F],
    ) -> RlweMultRgswProof<F> {
        let mut decomposed_bits = DecomposedBits::from_info(&instance.decomposed_bits_info);
        decomposed_bits.add_decomposed_bits_instance(&instance.bits_rlwe.a_bits);
        decomposed_bits.add_decomposed_bits_instance(&instance.bits_rlwe.b_bits);

        let uniform = <FieldUniformSampler<F>>::new();
        
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.ntt_instance.log_n);
        let identity_func_at_u = Rc::new(gen_identity_evaluations(u));
        
        // TODO sample randomness via Fiat-Shamir RNG
        let r_1 = uniform.sample(fs_rng);
        let r_2 = uniform.sample(fs_rng);
        instance.bits_rlwe_ntt.a_bits.iter().zip(instance.bits_rlwe_ntt.b_bits.iter())
            .zip(instance.bits_rgsw_c_ntt.a_bits.iter()).zip(instance.bits_rgsw_f_ntt.a_bits.iter())
            .for_each(|(((a, b), c), f)| {
                let prod1 = [
                    Rc::clone(a),
                    Rc::clone(c),
                    Rc::clone(&identity_func_at_u),
                ];
                let prod2 = [
                    Rc::clone(b),
                    Rc::clone(f),
                    Rc::clone(&identity_func_at_u),
                ];
                poly.add_product(prod1, r_1);
                poly.add_product(prod2, r_1);
            });
        
        instance.bits_rlwe_ntt.a_bits.iter().zip(instance.bits_rlwe_ntt.b_bits.iter())
            .zip(instance.bits_rgsw_c_ntt.b_bits.iter()).zip(instance.bits_rgsw_f_ntt.b_bits.iter())
            .for_each(|(((a, b), c), f)| {
                let prod1 = [
                    Rc::clone(a),
                    Rc::clone(c),
                    Rc::clone(&identity_func_at_u),
                ];
                let prod2 = [
                    Rc::clone(b),
                    Rc::clone(f),
                    Rc::clone(&identity_func_at_u),
                ];
                poly.add_product(prod1, r_2);
                poly.add_product(prod2, r_2);
            });

        poly.add_product([
            Rc::clone(&instance.output_rlwe_ntt.a),
            Rc::clone(&identity_func_at_u),
        ], r_1);
        poly.add_product([
            Rc::clone(&instance.output_rlwe_ntt.b),
            Rc::clone(&identity_func_at_u),
        ], r_2);

        RlweMultRgswProof {
            bit_decomposition_proof: BitDecomposition::prove_as_subprotocol(fs_rng, &decomposed_bits, u),
            ntt_proof: NTTIOP::prove_as_subprotocol(fs_rng, &instance.ntt_instance, u),
            sumcheck_msg: MLSumcheck::prove_as_subprotocol(fs_rng, &poly).expect("sumcheck fail in rlwe * rgsw").0,
        }
    }

    /// 
    pub fn verify(
        proof: &RlweMultRgswProof<F>,
        randomness_ntt: &[F],
        u: &[F],
        info: &RlweMultRgswInfo<F>,
    ) -> RlweMultRgswSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verify_as_subprotocol(&mut fs_rng, proof, randomness_ntt, u, info)
    }

    ///
    pub fn verify_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &RlweMultRgswProof<F>,
        randomness_ntt: &[F],
        u: &[F],
        info: &RlweMultRgswInfo<F>,
    ) -> RlweMultRgswSubclaim<F> {
        let uniform = <FieldUniformSampler<F>>::new();
        // TODO sample randomness via Fiat-Shamir RNG
        let r_1 = uniform.sample(fs_rng);
        let r_2 = uniform.sample(fs_rng);
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: info.ntt_info.log_n,
        };
        let subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::ZERO, &proof.sumcheck_msg)
                .expect("sumcheck protocol in rlwe mult rgsw failed");
        RlweMultRgswSubclaim {
            bit_decomposition_subcliam: BitDecomposition::verifier_as_subprotocol(fs_rng, &proof.bit_decomposition_proof, &info.decomposed_bits_info),
            ntt_subclaim: NTTIOP::verify_as_subprotocol(fs_rng, &proof.ntt_proof, &info.ntt_info, u),
            randomness_ntt: randomness_ntt.to_owned(),
            randomness_sumcheck: vec![r_1, r_2],
            point: subclaim.point,
            expected_evaluation: subclaim.expected_evaluations,
        }
    }
}
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
use super::{
    ntt::{BatchNTTInstanceInfoClean, BitsOrder, NTTRecursiveProof},
    BatchNTTInstanceInfo, BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo, LookupInstance, LookupInstanceEval, LookupInstanceInfo,
    NTTBareIOP, NTTInstance, NTTIOP,
};
use crate::piop::LookupIOP;
use crate::sumcheck::{self, verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    add_assign_ef, eval_identity_function, gen_identity_evaluations, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use bincode::Result;
use core::fmt;
use itertools::izip;
use pcs::PolynomialCommitmentScheme;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

/// Stores the multiplication instance between RLWE ciphertext and RGSW ciphertext with the corresponding NTT table
/// Given (a, b) \in RLWE where a and b are two polynomials represented by N coefficients,
/// and (c, f) \in RGSW = RLWE' \times RLWE' = (RLWE, ..., RLWE) \times (RLWE, ..., RLWE) where c = ((c0, c0'), ..., (ck-1, ck-1')) and f = ((f0, f0'), ..., (fk-1, fk-1'))
#[derive(Debug, Clone)]
pub struct ExternalProductInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// info of decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// info of ntt instance
    pub ntt_info: BatchNTTInstanceInfo<F>,
    /// Store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    pub input_rlwe: RlweCiphertext<F>,
    /// a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    pub bits_rlwe: RlweCiphertextVector<F>,
    /// The ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlweCiphertextVector<F>,
    /// The ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlweCiphertextVector<F>,
    /// The ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlweCiphertextVector<F>,
    /// Store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweCiphertext<F>,
}

/// Evaluation of RlweMultRgsw at the same random point
#[derive(Serialize, Deserialize)]
pub struct ExternalProductInstanceEval<F: Field> {
    /// The Length of bits when decomposing bits
    pub bits_len: usize,
    /// Store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    pub input_rlwe: RlweEval<F>,
    /// a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    pub bits_rlwe: RlwesEval<F>,
    /// The ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlwesEval<F>,
    /// The ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlwesEval<F>,
    /// The ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlwesEval<F>,
    /// Store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweEval<F>,
}

/// Evaluation of RlweCiphertext at the same random point
pub type RlweEval<F> = (F, F);
/// Evaluation of RlweCiphertexts at the same random point
pub type RlwesEval<F> = (Vec<F>, Vec<F>);

/// store the information used to verify
#[derive(Clone)]
pub struct ExternalProductInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// information of ntt instance
    pub ntt_info: BatchNTTInstanceInfo<F>,
    /// information of bit decomposition
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for ExternalProductInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "An instance of RLWE * RGSW: #vars = {}", self.num_vars)?;
        write!(f, "- containing ")?;
        self.bits_info.fmt(f)?;
        write!(f, "\n- containing")?;
        self.ntt_info.fmt(f)
    }
}

impl<F: Field> ExternalProductInstanceInfo<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + 8 * self.bits_info.bits_len
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

    /// Convert to EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> ExternalProductInstanceInfo<EF> {
        ExternalProductInstanceInfo::<EF> {
            num_vars: self.num_vars,
            ntt_info: self.ntt_info.to_ef::<EF>(),
            bits_info: self.bits_info.to_ef::<EF>(),
        }
    }

    /// Convert to clean info.
    #[inline]
    pub fn to_clean(&self) -> ExternalProductInstanceInfoClean<F> {
        ExternalProductInstanceInfoClean::<F> {
            num_vars: self.num_vars,
            ntt_info_clean: self.ntt_info.to_clean(),
            bits_info: self.bits_info.clone(),
        }
    }

    /// Extract lookup info.
    #[inline]
    pub fn extract_lookup_info(&self, block_size: usize) -> LookupInstanceInfo {
        LookupInstanceInfo {
            num_vars: self.num_vars,
            num_batch: 2 * self.bits_info.bits_len,
            block_size,
            block_num: (2 * self.bits_info.bits_len + block_size) / block_size,
        }
    }
}

/// Stores the information to be hashed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalProductInstanceInfoClean<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// information of ntt instance
    pub ntt_info_clean: BatchNTTInstanceInfoClean,
    /// information of bit decomposition
    pub bits_info: BitDecompositionInstanceInfo<F>,
}
/// RLWE ciphertext (a, b) where a and b represent two polynomials in some defined polynomial ring.
/// Note that it can represent either in coefficient or NTT form.
#[derive(Debug, Clone)]
pub struct RlweCiphertext<F: Field> {
    /// The first part of the rlwe ciphertext.
    pub a: DenseMultilinearExtension<F>,
    /// The second part of the rlwe ciphertext.
    pub b: DenseMultilinearExtension<F>,
}
impl<F: Field> RlweCiphertext<F> {
    /// Pack mles
    #[inline]
    pub fn pack_all_mles(&self) -> Vec<F> {
        self.a
            .iter()
            .chain(self.b.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Convert to an EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> RlweCiphertext<EF> {
        RlweCiphertext::<EF> {
            a: self.a.to_ef::<EF>(),
            b: self.b.to_ef::<EF>(),
        }
    }

    /// Evaluate at the same random point defined F
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> RlweEval<F> {
        (self.a.evaluate(point), self.b.evaluate(point))
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(&self, point: &[EF]) -> RlweEval<EF> {
        (self.a.evaluate_ext(point), self.b.evaluate_ext(point))
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> RlweEval<EF> {
        (
            self.a.evaluate_ext_opt(point),
            self.b.evaluate_ext_opt(point),
        )
    }
}

/// RLWE' ciphertexts represented by two vectors, containing k RLWE ciphertext.
#[derive(Debug, Clone)]
pub struct RlweCiphertextVector<F: Field> {
    /// Store the first part of each RLWE ciphertext vector.
    pub a_vector: Vec<DenseMultilinearExtension<F>>,
    /// Store the second part of each RLWE ciphertext vector.
    pub b_vector: Vec<DenseMultilinearExtension<F>>,
}
impl<F: Field> RlweCiphertextVector<F> {
    /// Construct an empty rlweciphertexts
    ///
    /// # Arguments.
    ///
    /// * `bits_len` - the decomposition bits length.
    pub fn new(bits_len: usize) -> Self {
        Self {
            a_vector: Vec::with_capacity(bits_len),
            b_vector: Vec::with_capacity(bits_len),
        }
    }

    /// Add a RLWE ciphertext
    ///
    /// # Arguments.
    ///
    /// * `a` - MLE of rlwe a.
    /// * `b` - MLE of rlwe b.
    pub fn add_rlwe_instance(
        &mut self,
        a: DenseMultilinearExtension<F>,
        b: DenseMultilinearExtension<F>,
    ) {
        self.a_vector.push(a);
        self.b_vector.push(b);
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        if self.a_vector.is_empty() || self.b_vector.is_empty() {
            return true;
        }
        false
    }

    /// Return the len
    pub fn len(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        assert_eq!(self.a_vector.len(), self.b_vector.len());
        self.a_vector.len()
    }

    /// Returns a vector that iterates over the evaluations over {0,1}^`num_vars`
    #[inline]
    pub fn pack_all_mles(&self) -> Vec<F> {
        self.a_vector
            .iter()
            .flat_map(|bit| bit.iter())
            .chain(self.b_vector.iter().flat_map(|bit| bit.iter()))
            .copied()
            .collect()
    }

    /// Convert to EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> RlweCiphertextVector<EF> {
        RlweCiphertextVector::<EF> {
            a_vector: self.a_vector.iter().map(|bit| bit.to_ef::<EF>()).collect(),
            b_vector: self.b_vector.iter().map(|bit| bit.to_ef::<EF>()).collect(),
        }
    }

    /// Evaluate at the same random point defined over F
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> RlwesEval<F> {
        (
            self.a_vector
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
            self.b_vector
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
        )
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(&self, point: &[EF]) -> RlwesEval<EF> {
        (
            self.a_vector
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
            self.b_vector
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
        )
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> RlwesEval<EF> {
        (
            self.a_vector
                .iter()
                .map(|bit| bit.evaluate_ext_opt(point))
                .collect(),
            self.b_vector
                .iter()
                .map(|bit| bit.evaluate_ext_opt(point))
                .collect(),
        )
    }
}

impl<F: Field> ExternalProductInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> ExternalProductInstanceInfo<F> {
        ExternalProductInstanceInfo {
            num_vars: self.num_vars,
            ntt_info: self.ntt_info.clone(),
            bits_info: self.bits_info.clone(),
        }
    }

    /// Construct the instance from reference
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        num_vars: usize,
        bits_info: BitDecompositionInstanceInfo<F>,
        ntt_info: BatchNTTInstanceInfo<F>,
        input_rlwe: RlweCiphertext<F>,
        bits_rlwe: RlweCiphertextVector<F>,
        bits_rlwe_ntt: RlweCiphertextVector<F>,
        bits_rgsw_c_ntt: RlweCiphertextVector<F>,
        bits_rgsw_f_ntt: RlweCiphertextVector<F>,
        output_rlwe_ntt: RlweCiphertext<F>,
        // output_rlwe: &RlweCiphertext<F>,
    ) -> Self {
        // update num_ntt of ntt_info
        let ntt_info = BatchNTTInstanceInfo {
            num_ntt: bits_info.bits_len << 1,
            num_vars,
            ntt_table: ntt_info.ntt_table,
        };

        assert_eq!(bits_rlwe.len(), bits_info.bits_len);
        assert_eq!(bits_rlwe_ntt.len(), bits_info.bits_len);
        assert_eq!(bits_rgsw_c_ntt.len(), bits_info.bits_len);
        assert_eq!(bits_rgsw_f_ntt.len(), bits_info.bits_len);
        // update num_instance of bits_info
        let bits_info = BitDecompositionInstanceInfo {
            num_vars,
            base: bits_info.base,
            base_len: bits_info.base_len,
            bits_len: bits_info.bits_len,
            num_instances: 2,
        };

        ExternalProductInstance {
            num_vars,
            bits_info,
            ntt_info,
            input_rlwe,
            bits_rlwe,
            bits_rlwe_ntt,
            bits_rgsw_c_ntt,
            bits_rgsw_f_ntt,
            output_rlwe_ntt,
            // output_rlwe: output_rlwe.clone(),
        }
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    #[inline]
    pub fn pack_all_mles(&self) -> Vec<F> {
        let mut res = Vec::new();
        res.append(&mut self.input_rlwe.pack_all_mles());
        res.append(&mut self.output_rlwe_ntt.pack_all_mles());
        res.append(&mut self.bits_rlwe.pack_all_mles());
        res.append(&mut self.bits_rlwe_ntt.pack_all_mles());
        res.append(&mut self.bits_rgsw_c_ntt.pack_all_mles());
        res.append(&mut self.bits_rgsw_f_ntt.pack_all_mles());
        res
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.xw
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let info = self.info();
        let num_vars = info.generate_num_var();
        let num_zeros_padded = (1 << num_vars) - info.num_oracles() * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct an EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> ExternalProductInstance<EF> {
        ExternalProductInstance::<EF> {
            num_vars: self.num_vars,
            bits_info: self.bits_info.to_ef::<EF>(),
            ntt_info: self.ntt_info.to_ef::<EF>(),
            input_rlwe: self.input_rlwe.to_ef::<EF>(),
            bits_rlwe: self.bits_rlwe.to_ef::<EF>(),
            bits_rlwe_ntt: self.bits_rlwe_ntt.to_ef::<EF>(),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.to_ef::<EF>(),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.to_ef::<EF>(),
            output_rlwe_ntt: self.output_rlwe_ntt.to_ef::<EF>(),
        }
    }

    /// Evaluate at the same random point defined over F
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> ExternalProductInstanceEval<F> {
        ExternalProductInstanceEval::<F> {
            bits_len: self.bits_info.bits_len,
            input_rlwe: self.input_rlwe.evaluate(point),
            bits_rlwe: self.bits_rlwe.evaluate(point),
            bits_rlwe_ntt: self.bits_rlwe_ntt.evaluate(point),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.evaluate(point),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.evaluate(point),
            output_rlwe_ntt: self.output_rlwe_ntt.evaluate(point),
        }
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> ExternalProductInstanceEval<EF> {
        ExternalProductInstanceEval::<EF> {
            bits_len: self.bits_info.bits_len,
            input_rlwe: self.input_rlwe.evaluate_ext(point),
            bits_rlwe: self.bits_rlwe.evaluate_ext(point),
            bits_rlwe_ntt: self.bits_rlwe_ntt.evaluate_ext(point),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.evaluate_ext(point),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.evaluate_ext(point),
            output_rlwe_ntt: self.output_rlwe_ntt.evaluate_ext(point),
        }
    }

    /// Evaluate given the equality function
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> ExternalProductInstanceEval<EF> {
        ExternalProductInstanceEval::<EF> {
            bits_len: self.bits_info.bits_len,
            input_rlwe: self.input_rlwe.evaluate_ext_opt(point),
            bits_rlwe: self.bits_rlwe.evaluate_ext_opt(point),
            bits_rlwe_ntt: self.bits_rlwe_ntt.evaluate_ext_opt(point),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.evaluate_ext_opt(point),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.evaluate_ext_opt(point),
            output_rlwe_ntt: self.output_rlwe_ntt.evaluate_ext_opt(point),
        }
    }

    /// Return the number of ntt instances contained
    #[inline]
    pub fn num_ntt_contained(&self) -> usize {
        self.ntt_info.num_ntt
    }

    /// Extract all NTT instances into a single random NTT instance to be proved
    #[inline]
    pub fn extract_ntt_instance(&self, randomness: &[F]) -> NTTInstance<F> {
        assert_eq!(randomness.len(), self.num_ntt_contained());
        let mut random_coeffs = <DenseMultilinearExtension<F>>::from_evaluations_vec(
            self.num_vars,
            vec![F::zero(); 1 << self.num_vars],
        );
        let mut random_points = <DenseMultilinearExtension<F>>::from_evaluations_vec(
            self.num_vars,
            vec![F::zero(); 1 << self.num_vars],
        );

        self.update_ntt_instance(&mut random_coeffs, &mut random_points, randomness);

        NTTInstance::<F> {
            num_vars: self.num_vars,
            ntt_table: self.ntt_info.ntt_table.clone(),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Update the NTT instance to be proved
    #[inline]
    pub fn update_ntt_instance(
        &self,
        r_coeffs: &mut DenseMultilinearExtension<F>,
        r_points: &mut DenseMultilinearExtension<F>,
        randomness: &[F],
    ) {
        for (r, coeff, point) in izip!(
            randomness,
            self.bits_rlwe
                .a_vector
                .iter()
                .chain(self.bits_rlwe.b_vector.iter()),
            self.bits_rlwe_ntt
                .a_vector
                .iter()
                .chain(self.bits_rlwe_ntt.b_vector.iter())
        ) {
            *r_coeffs += (*r, coeff);
            *r_points += (*r, point);
        }
    }

    /// Extract all NTT instances into a single random NTT defined over EF instance to be proved
    #[inline]
    pub fn extract_ntt_instance_to_ef<EF: AbstractExtensionField<F>>(
        &self,
        randomness: &[EF],
    ) -> NTTInstance<EF> {
        assert_eq!(randomness.len(), self.num_ntt_contained());
        let mut random_coeffs = <DenseMultilinearExtension<EF>>::from_evaluations_vec(
            self.num_vars,
            vec![EF::zero(); 1 << self.num_vars],
        );
        let mut random_points = <DenseMultilinearExtension<EF>>::from_evaluations_vec(
            self.num_vars,
            vec![EF::zero(); 1 << self.num_vars],
        );

        self.update_ntt_instance_to_ef::<EF>(&mut random_coeffs, &mut random_points, randomness);

        NTTInstance::<EF> {
            num_vars: self.num_vars,
            ntt_table: Arc::new(
                self.ntt_info
                    .ntt_table
                    .iter()
                    .map(|x| EF::from_base(*x))
                    .collect(),
            ),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Update NTT instance to be proved
    #[inline]
    pub fn update_ntt_instance_to_ef<EF: AbstractExtensionField<F>>(
        &self,
        r_coeffs: &mut DenseMultilinearExtension<EF>,
        r_points: &mut DenseMultilinearExtension<EF>,
        randomness: &[EF],
    ) {
        for (r, coeff, point) in izip!(
            randomness,
            self.bits_rlwe
                .a_vector
                .iter()
                .chain(self.bits_rlwe.b_vector.iter()),
            self.bits_rlwe_ntt
                .a_vector
                .iter()
                .chain(self.bits_rlwe_ntt.b_vector.iter())
        ) {
            // multiplication between EF (r) and F (y)
            add_assign_ef::<F, EF>(r_coeffs, r, coeff);
            add_assign_ef::<F, EF>(r_points, r, point);
        }
    }

    /// Extract DecomposedBits instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionInstance<F> {
        let mut res = BitDecompositionInstance {
            base: self.bits_info.base,
            base_len: self.bits_info.base_len,
            bits_len: self.bits_info.bits_len,
            num_vars: self.num_vars,
            d_val: Vec::with_capacity(2),
            d_bits: Vec::with_capacity(2 * self.bits_info.bits_len),
        };
        self.update_decomposed_bits(&mut res);
        res
    }

    /// Update DecomposedBits Instance
    #[inline]
    pub fn update_decomposed_bits(&self, decomposed_bits: &mut BitDecompositionInstance<F>) {
        decomposed_bits.add_decomposed_bits_instance(
            &Rc::new(self.input_rlwe.a.clone()),
            &self
                .bits_rlwe
                .a_vector
                .iter()
                .map(|bits| Rc::new(bits.clone()))
                .collect::<Vec<_>>(),
        );
        decomposed_bits.add_decomposed_bits_instance(
            &Rc::new(self.input_rlwe.b.clone()),
            &self
                .bits_rlwe
                .b_vector
                .iter()
                .map(|bits| Rc::new(bits.clone()))
                .collect::<Vec<_>>(),
        );
    }

    /// Extract lookup instance
    #[inline]
    pub fn extract_lookup_instance(&self, block_size: usize) -> LookupInstance<F> {
        self.extract_decomposed_bits()
            .extract_lookup_instance(block_size)
    }
}

impl<F: Field> ExternalProductInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + 8 * self.bits_len
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
        res.extend([
            self.input_rlwe.0,
            self.input_rlwe.1,
            self.output_rlwe_ntt.0,
            self.output_rlwe_ntt.1,
        ]);
        res.extend(self.bits_rlwe.0.iter());
        res.extend(self.bits_rlwe.1.iter());
        res.extend(self.bits_rlwe_ntt.0.iter());
        res.extend(self.bits_rlwe_ntt.1.iter());
        res.extend(self.bits_rgsw_c_ntt.0.iter());
        res.extend(self.bits_rgsw_c_ntt.1.iter());
        res.extend(self.bits_rgsw_f_ntt.0.iter());
        res.extend(self.bits_rgsw_f_ntt.1.iter());
        res
    }

    /// Extract DecomposedBits Instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionEval<F> {
        let mut res = BitDecompositionEval {
            d_val: Vec::with_capacity(2),
            d_bits: Vec::new(),
        };
        self.update_decomposed_bits(&mut res);
        res
    }

    /// Update DecomposedBits with added bits in this instance
    #[inline]
    pub fn update_decomposed_bits(&self, bits_evals: &mut BitDecompositionEval<F>) {
        bits_evals.d_val.push(self.input_rlwe.0);
        bits_evals.d_val.push(self.input_rlwe.1);
        bits_evals.d_bits.extend(&self.bits_rlwe.0);
        bits_evals.d_bits.extend(&self.bits_rlwe.1);
    }

    /// Extract the NTT-Coefficient evaluation
    #[inline]
    pub fn update_ntt_instance_coeff(&self, r_coeff: &mut F, randomness: &[F]) {
        assert_eq!(
            randomness.len(),
            self.bits_rlwe.0.len() + self.bits_rlwe.1.len()
        );
        *r_coeff += self
            .bits_rlwe
            .0
            .iter()
            .chain(self.bits_rlwe.1.iter())
            .zip(randomness)
            .fold(F::zero(), |acc, (coeff, r)| acc + *r * *coeff);
    }

    /// Extract the NTT-Coefficient evaluation
    #[inline]
    pub fn update_ntt_instance_point(&self, r_point: &mut F, randomness: &[F]) {
        assert_eq!(
            randomness.len(),
            self.bits_rlwe_ntt.0.len() + self.bits_rlwe_ntt.1.len()
        );
        *r_point += self
            .bits_rlwe_ntt
            .0
            .iter()
            .chain(self.bits_rlwe_ntt.1.iter())
            .zip(randomness)
            .fold(F::zero(), |acc, (coeff, r)| acc + *r * *coeff);
    }
}

/// IOP for RLWE * RGSW
#[derive(Default)]
pub struct ExternalProductIOP<F: Field> {
    /// The random vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random vector for ntt.
    pub randomness_ntt: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> ExternalProductIOP<F> {
    /// Sample the random coins before proving sumcheck protocol
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    #[inline]
    pub fn sample_coins(trans: &mut Transcript<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(),
        )
    }

    /// Return the number of coins used in sumcheck protocol
    #[inline]
    pub fn num_coins() -> usize {
        2
    }

    /// Generate the randomness.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The external product instance info.
    #[inline]
    pub fn generate_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        info: &ExternalProductInstanceInfo<F>,
    ) {
        self.randomness = Self::sample_coins(trans);
        self.randomness_ntt = NTTIOP::<F>::sample_coins(trans, &info.ntt_info.to_clean());
        self.u = trans.get_vec_challenge(
            b"EP IOP: random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// Prove external product instance
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `instance` - The external product instance.
    /// * `lookup_instance` - The extracted lookup instance.
    /// * `lookup_iop` - The lookup IOP.
    /// * `bits_order` - The indicator of bits order.
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &ExternalProductInstance<F>,
        lookup_instance: &LookupInstance<F>,
        lookup_iop: &LookupIOP<F>,
        bits_order: BitsOrder,
    ) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        // add sumcheck products (without NTT) into poly
        Self::prepare_products_of_polynomial(&self.randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck products of NTT into poly
        let ntt_instance = instance.extract_ntt_instance(&self.randomness_ntt);
        NTTBareIOP::<F>::prepare_products_of_polynomial(
            F::one(),
            &mut poly,
            &mut claimed_sum,
            &ntt_instance,
            &self.u,
            bits_order,
        );

        LookupIOP::<F>::prepare_products_of_polynomial(
            &lookup_iop.randomness,
            &mut poly,
            lookup_instance,
            &eq_at_u,
        );

        // prove all sumcheck protocol into a large random sumcheck
        let (proof, state) =
            MLSumcheck::prove(trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof = NTTIOP::<F>::prove_recursion(
            trans,
            &state.randomness,
            &ntt_instance.info(),
            &self.u,
            bits_order,
        );

        (
            SumcheckKit {
                proof,
                claimed_sum,
                info: poly.info(),
                u: self.u.clone(),
                randomness: state.randomness,
            },
            recursive_proof,
        )
    }

    /// Prove RLWE * RGSW with leaving the NTT part outside this interface
    #[inline]
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &ExternalProductInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let r = randomness;
        assert_eq!(r.len(), 2);

        // Integrate the second part of Sumcheck
        // Sumcheck for proving g'(x) = \sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) for x \in \{0, 1\}^\log n.
        // Prover claims the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
        // where u is randomly sampled by the verifier.
        for (a, b, c, f) in izip!(
            &instance.bits_rlwe_ntt.a_vector,
            &instance.bits_rlwe_ntt.b_vector,
            &instance.bits_rgsw_c_ntt.a_vector,
            &instance.bits_rgsw_f_ntt.a_vector
        ) {
            let prod1 = [Rc::new(a.clone()), Rc::new(c.clone()), Rc::clone(eq_at_u)];
            let prod2 = [Rc::new(b.clone()), Rc::new(f.clone()), Rc::clone(eq_at_u)];
            poly.add_product(prod1, r[0]);
            poly.add_product(prod2, r[0]);
        }
        poly.add_product(
            [
                Rc::new(instance.output_rlwe_ntt.a.clone()),
                Rc::clone(eq_at_u),
            ],
            -r[0],
        );

        // Sumcheck protocol for proving: h' = \sum_{i = 0}^{k-1} a_i' \cdot c_i' + b_i' \cdot f_i'
        for (a, b, c, f) in izip!(
            &instance.bits_rlwe_ntt.a_vector,
            &instance.bits_rlwe_ntt.b_vector,
            &instance.bits_rgsw_c_ntt.b_vector,
            &instance.bits_rgsw_f_ntt.b_vector
        ) {
            let prod1 = [Rc::new(a.clone()), Rc::new(c.clone()), Rc::clone(eq_at_u)];
            let prod2 = [Rc::new(b.clone()), Rc::new(f.clone()), Rc::clone(eq_at_u)];
            poly.add_product(prod1, r[1]);
            poly.add_product(prod2, r[1]);
        }
        poly.add_product(
            [
                Rc::new(instance.output_rlwe_ntt.b.clone()),
                Rc::clone(eq_at_u),
            ],
            -r[1],
        );
    }

    /// Verify external product proof.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `wrapper` - The proof wrapper.
    /// * `evals_at_r` - The evaluation points at r.
    /// * `evals_at_u` - The evaluation points at u.
    /// * `info` - The external product info.
    /// * `lookup_info` - The derived lookup info.
    /// * `recursive_proof` - The recursive sumcheck proof.
    /// * `lookup_evals` - The extracted lookup instance evaluations.
    /// * `lookup_iop` - The lookup IOP.
    /// * `bits_order` - The indicator of bits order.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &ExternalProductInstanceEval<F>,
        evals_at_u: &ExternalProductInstanceEval<F>,
        info: &ExternalProductInstanceInfo<F>,
        lookup_info: &LookupInstanceInfo,
        recursive_proof: &NTTRecursiveProof<F>,
        lookup_evals: &LookupInstanceEval<F>,
        lookup_iop: &LookupIOP<F>,
        bits_order: BitsOrder,
    ) -> (bool, Vec<F>) {
        let mut subclaim =
            MLSumcheck::verify(trans, &wrapper.info, wrapper.claimed_sum, &wrapper.proof)
                .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&self.u, &subclaim.point);

        // check the sumcheck evaluation (without NTT)
        if !Self::verify_subclaim(&self.randomness, &mut subclaim, evals_at_r, info, eq_at_u_r) {
            return (false, vec![]);
        }

        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        // one is to evaluate the random linear combination of evaluations at point r returned from sumcheck protocol
        let mut ntt_coeff_evals_at_r = F::zero();
        evals_at_r.update_ntt_instance_coeff(&mut ntt_coeff_evals_at_r, &self.randomness_ntt);
        // the other is to evaluate the random linear combination of evaluations at point u sampled before the sumcheck protocol
        let mut ntt_point_evals_at_u = F::zero();
        evals_at_u.update_ntt_instance_point(&mut ntt_point_evals_at_u, &self.randomness_ntt);

        if !NTTBareIOP::<F>::verify_subclaim(
            F::one(),
            &mut subclaim,
            &mut wrapper.claimed_sum,
            ntt_coeff_evals_at_r,
            ntt_point_evals_at_u,
            f_delegation,
        ) {
            return (false, vec![]);
        }

        if !LookupIOP::<F>::verify_subclaim(
            &lookup_iop.randomness,
            &mut subclaim,
            lookup_evals,
            lookup_info,
            eq_at_u_r,
        ) {
            return (false, vec![]);
        }
        if !(subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()) {
            return (false, vec![]);
        }
        let res = NTTIOP::<F>::verify_recursion(
            trans,
            recursive_proof,
            &info.ntt_info,
            &self.u,
            &subclaim.point,
            bits_order,
        );

        (res, subclaim.point)
    }

    /// Verify RLWE * RGSW with leaving NTT part outside of the interface
    #[inline]
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &ExternalProductInstanceEval<F>,
        info: &ExternalProductInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        // 1. check the bit decomposition part
        let bits_eval = evals.extract_decomposed_bits();
        // let bits_r_num = <BitDecomposition<F>>::num_coins(&info.bits_info);
        // let (r_ntt, r) = randomness.split_at(bits_r_num);
        let check_decomposed_bits = <BitDecompositionIOP<F>>::verify_subclaim_without_range_check(
            &bits_eval,
            &info.bits_info,
        );
        if !check_decomposed_bits {
            return false;
        }

        let r = randomness;
        // 2. check the rest sumcheck protocols
        // The first part is to evaluate at a random point g' = \sum_{i = 0}^{k-1} a_i' \cdot c_i + b_i' \cdot f_i
        // It is the reduction claim of prover asserting the sum \sum_{x} eq(u, x) (\sum_{i = 0}^{k-1} a_i'(x) \cdot c_i(x) + b_i'(x) \cdot f_i(x) - g'(x)) = 0
        let mut sum1 = F::zero();
        let mut sum2 = F::zero();
        for (a, b, c, f) in izip!(
            &evals.bits_rlwe_ntt.0,
            &evals.bits_rlwe_ntt.1,
            &evals.bits_rgsw_c_ntt.0,
            &evals.bits_rgsw_f_ntt.0
        ) {
            sum1 += *a * *c + *b * *f;
        }

        for (a, b, c, f) in izip!(
            &evals.bits_rlwe_ntt.0,
            &evals.bits_rlwe_ntt.1,
            &evals.bits_rgsw_c_ntt.1,
            &evals.bits_rgsw_f_ntt.1
        ) {
            sum2 += *a * *c + *b * *f;
        }

        subclaim.expected_evaluations -= eq_at_u_r
            * (r[0] * (sum1 - evals.output_rlwe_ntt.0) + r[1] * (sum2 - evals.output_rlwe_ntt.1));
        true
    }
}

/// External product proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct ExternalProductProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Polynomial info.
    pub poly_info: PolynomialInfo,
    /// The first polynomial commitment.
    pub first_comm: Pcs::Commitment,
    /// The evaluation of the first packed polynomial.
    pub first_oracle_eval_at_r: EF,
    /// The opening of the first polynomial.
    pub first_eval_proof_at_r: Pcs::Proof,
    /// The evaluation of the first packed polynomial.
    pub first_oracle_eval_at_u: EF,
    /// The opening of the first polynomial.
    pub first_eval_proof_at_u: Pcs::Proof,
    /// The second polynomial commitment.
    pub second_comm: Pcs::Commitment,
    /// The evaluation of the second packed polynomial.
    pub second_oracle_eval: EF,
    /// The opening proof of the second polynomial.
    pub second_eval_proof: Pcs::ProofEF,
    /// The sumcheck proof.
    pub sumcheck_proof: sumcheck::Proof<EF>,
    /// NTT recursive proof.
    pub recursive_proof: NTTRecursiveProof<EF>,
    /// The external product evaluations.
    pub ep_evals_at_r: ExternalProductInstanceEval<EF>,
    /// The external product evaluations.
    pub ep_evals_at_u: ExternalProductInstanceEval<EF>,
    /// The lookup evaluations.
    pub lookup_evals: LookupInstanceEval<EF>,
    /// The claimed sum from sumcheck.
    pub claimed_sum: EF,
}

impl<F, EF, S, Pcs> ExternalProductProof<F, EF, S, Pcs>
where
    F: Field,
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

/// External product parameters.
pub struct ExternalProductParams<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// The parameters for the first polynomial.
    pub pp_first: Pcs::Parameters,
    /// The parameters for the second polynomial.
    pub pp_second: Pcs::Parameters,
}

impl<F, EF, S, Pcs> Default for ExternalProductParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        Self {
            pp_first: Pcs::Parameters::default(),
            pp_second: Pcs::Parameters::default(),
        }
    }
}

impl<F, EF, S, Pcs> ExternalProductParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    pub fn setup(
        &mut self,
        info: &ExternalProductInstanceInfo<F>,
        block_size: usize,
        code_spec: S,
    ) {
        self.pp_first = Pcs::setup(info.generate_num_var(), Some(code_spec.clone()));

        let lookup_info = info.extract_lookup_info(block_size);
        self.pp_second = Pcs::setup(lookup_info.generate_second_num_var(), Some(code_spec));
    }
}

/// Prover for external product with PCS.
pub struct ExternalProductProver<
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

impl<F, EF, S, Pcs> Default for ExternalProductProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        ExternalProductProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> ExternalProductProver<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<
        F,
        EF,
        S,
        Polynomial = DenseMultilinearExtension<F>,
        EFPolynomial = DenseMultilinearExtension<EF>,
        Point = EF,
    >,
{
    /// The prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<EF>,
        params: &ExternalProductParams<F, EF, S, Pcs>,
        instance: &ExternalProductInstance<F>,
        block_size: usize,
        bits_order: BitsOrder,
    ) -> ExternalProductProof<F, EF, S, Pcs> {
        let instance_info = instance.info();
        // It is better to hash the shared public instance information, including the table.
        trans.append_message(b"extenral product instance", &instance_info.to_clean());

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let first_committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (first_comm, first_comm_state) = Pcs::commit(&params.pp_first, &first_committed_poly);

        trans.append_message(b"EP IOP: first commitment", &first_comm);

        // Convert the original instance into an instance defined over EF
        let instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // IOPs
        let mut ep_iop = ExternalProductIOP::<EF>::default();
        let mut lookup_iop = LookupIOP::<EF>::default();

        // generate ranomness for EP iop.
        ep_iop.generate_randomness(trans, &instance_info);

        // --- Lookup instance and commitment ---
        let mut lookup_instance = instance_ef.extract_lookup_instance(block_size);
        let lookup_info = lookup_instance.info();

        // Generate the first randomness for lookup iop.
        lookup_iop.prover_generate_first_randomness(trans, &mut lookup_instance);

        // Compute the packed second polynomials for lookup, i.e., h vector.
        let second_committed_poly = lookup_instance.generate_second_oracle();

        // Commit the second polynomial.
        let (second_comm, second_comm_state) =
            Pcs::commit_ef(&params.pp_second, &second_committed_poly);

        trans.append_message(b"EP IOP: second commitment", &second_comm);

        lookup_iop.generate_second_randomness(trans, &lookup_info);

        let (kit, recursive_proof) = ep_iop.prove(
            trans,
            &instance_ef,
            &lookup_instance,
            &lookup_iop,
            bits_order,
        );

        let ep_evals_at_r = instance.evaluate_ext(&kit.randomness);
        let ep_evals_at_u = instance.evaluate_ext(&ep_iop.u);

        // let eq_at_r = gen_identity_evaluations(&kit.randomness);
        // let evals_at_r = instance.evaluate_ext_opt(&eq_at_r);
        // let evals_at_u = instance.evaluate_ext_opt(eq_at_u.as_ref());

        // Lookup evaluation
        let lookup_evals = lookup_instance.evaluate(&kit.randomness);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = kit.randomness.clone();
        let mut requested_point_at_u = ep_iop.u.clone();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.info().log_num_oracles(),
        );
        requested_point_at_r.extend(&oracle_randomness);
        requested_point_at_u.extend(&oracle_randomness);

        let first_oracle_eval_at_r = first_committed_poly.evaluate_ext(&requested_point_at_r);
        let first_oracle_eval_at_u = first_committed_poly.evaluate_ext(&requested_point_at_u);

        let mut second_requested_point = kit.randomness.clone();
        let second_oracle_randomness = trans.get_vec_challenge(
            b"Lookup IOP: random linear combination of evaluations of second oracles",
            lookup_info.log_num_second_oracles(),
        );

        second_requested_point.extend(&second_oracle_randomness);

        let second_oracle_eval = second_committed_poly.evaluate(&second_requested_point);

        // Generate the evaluation proof of the requested point
        let first_eval_proof_at_r = Pcs::open(
            &params.pp_first,
            &first_comm,
            &first_comm_state,
            &requested_point_at_r,
            trans,
        );
        let first_eval_proof_at_u = Pcs::open(
            &params.pp_first,
            &first_comm,
            &first_comm_state,
            &requested_point_at_u,
            trans,
        );

        let second_eval_proof = Pcs::open_ef(
            &params.pp_second,
            &second_comm,
            &second_comm_state,
            &second_requested_point,
            trans,
        );

        ExternalProductProof {
            poly_info: kit.info,
            first_comm,
            first_oracle_eval_at_r,
            first_eval_proof_at_r,
            first_oracle_eval_at_u,
            first_eval_proof_at_u,
            second_comm,
            second_oracle_eval,
            second_eval_proof,
            sumcheck_proof: kit.proof,
            recursive_proof,
            ep_evals_at_r,
            ep_evals_at_u,
            lookup_evals,
            claimed_sum: kit.claimed_sum,
        }
    }
}

/// Prover for external product with PCS.
pub struct ExternalProductVerifier<
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

impl<F, EF, S, Pcs> Default for ExternalProductVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        ExternalProductVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> ExternalProductVerifier<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<
        F,
        EF,
        S,
        Polynomial = DenseMultilinearExtension<F>,
        EFPolynomial = DenseMultilinearExtension<EF>,
        Point = EF,
    >,
{
    /// The verifier.
    pub fn verify(
        &self,
        trans: &mut Transcript<EF>,
        params: &ExternalProductParams<F, EF, S, Pcs>,
        info: &ExternalProductInstanceInfo<F>,
        block_size: usize,
        bits_order: BitsOrder,
        proof: &ExternalProductProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"extenral product instance", &info.to_clean());
        trans.append_message(b"EP IOP: first commitment", &proof.first_comm);

        let mut ep_iop = ExternalProductIOP::<EF>::default();
        let mut lookup_iop = LookupIOP::<EF>::default();
        let info_ef = info.to_ef();

        ep_iop.generate_randomness(trans, &info_ef);
        lookup_iop.verifier_generate_first_randomness(trans);

        trans.append_message(b"EP IOP: second commitment", &proof.second_comm);

        // Verify the proof of sumcheck protocol.
        let lookup_info = info.extract_lookup_info(block_size);
        lookup_iop.generate_second_randomness(trans, &lookup_info);

        let mut wrapper = ProofWrapper {
            claimed_sum: proof.claimed_sum,
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };
        let (b, randomness) = ep_iop.verify(
            trans,
            &mut wrapper,
            &proof.ep_evals_at_r,
            &proof.ep_evals_at_u,
            &info_ef,
            &lookup_info,
            &proof.recursive_proof,
            &proof.lookup_evals,
            &lookup_iop,
            bits_order,
        );
        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let mut request_point_at_r = randomness.clone();
        let mut request_point_at_u = ep_iop.u;
        let flatten_evals_at_r = proof.ep_evals_at_r.flatten();
        let flatten_evals_at_u = proof.ep_evals_at_u.flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            proof.ep_evals_at_r.log_num_oracles(),
        );

        request_point_at_r.extend(&oracle_randomness);
        request_point_at_u.extend(&oracle_randomness);

        res &= verify_oracle_relation(
            &flatten_evals_at_r,
            proof.first_oracle_eval_at_r,
            &oracle_randomness,
        );

        res &= verify_oracle_relation(
            &flatten_evals_at_u,
            proof.first_oracle_eval_at_u,
            &oracle_randomness,
        );

        let mut second_requested_point = randomness;
        let second_oracle_randomness = trans.get_vec_challenge(
            b"Lookup IOP: random linear combination of evaluations of second oracles",
            proof.lookup_evals.log_num_second_oracles(),
        );

        second_requested_point.extend(&second_oracle_randomness);

        res &= verify_oracle_relation(
            &proof.lookup_evals.h_vec,
            proof.second_oracle_eval,
            &second_oracle_randomness,
        );

        // Check the evaluation of a random point over the committed oracles.
        res &= Pcs::verify(
            &params.pp_first,
            &proof.first_comm,
            &request_point_at_r,
            proof.first_oracle_eval_at_r,
            &proof.first_eval_proof_at_r,
            trans,
        );

        res &= Pcs::verify(
            &params.pp_first,
            &proof.first_comm,
            &request_point_at_u,
            proof.first_oracle_eval_at_u,
            &proof.first_eval_proof_at_u,
            trans,
        );

        res &= Pcs::verify_ef(
            &params.pp_second,
            &proof.second_comm,
            &second_requested_point,
            proof.second_oracle_eval,
            &proof.second_eval_proof,
            trans,
        );

        res
    }
}

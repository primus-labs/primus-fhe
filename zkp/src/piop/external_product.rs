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
use super::ntt::BitsOrder;
use super::ntt::NTTRecursiveProof;
use super::LookupInstance;
use super::NTTBareIOP;
use super::{
    BatchNTTInstanceInfo, BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo, NTTInstance, NTTIOP,
};
use crate::piop::LookupIOP;
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::MLSumcheck;
use crate::sumcheck::ProofWrapper;
use crate::sumcheck::SumcheckKit;
use crate::utils::{
    add_assign_ef, eval_identity_function, gen_identity_evaluations, print_statistic,
    verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field,
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
use std::sync::Arc;
use std::time::Instant;
use std::vec;
/// IOP for RLWE * RGSW
pub struct ExternalProductIOP<F: Field>(PhantomData<F>);

/// SNARKs for RLWE * RGSW
pub struct ExternalProductSnarks<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);

/// IOP for RLWE * RGSW
pub struct ExternalProductIOPPure<F: Field>(PhantomData<F>);

/// SNARKs for RLWE * RGSW
pub struct ExternalProductSnarksOpt<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);
/// RLWE ciphertext (a, b) where a and b represents two polynomials in some defined polynomial ring.
/// Note that it can represent either a coefficient-form or a NTT-form.
#[derive(Debug, Clone)]
pub struct RlweCiphertext<F: Field> {
    /// The first part of the rlwe ciphertext.
    pub a: DenseMultilinearExtension<F>,
    /// The second part of the rlwe ciphertext.
    pub b: DenseMultilinearExtension<F>,
}

/// RLWE' ciphertexts represented by two vectors, containing k RLWE ciphertext.
#[derive(Debug, Clone)]
pub struct RlweCiphertextVector<F: Field> {
    /// store the first part of each RLWE ciphertext.
    pub a_vector: Vec<DenseMultilinearExtension<F>>,
    /// store the second part of each RLWE ciphertext.
    pub b_vector: Vec<DenseMultilinearExtension<F>>,
}

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
    /// rlwe = (a, b): store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    pub input_rlwe: RlweCiphertext<F>,
    /// bits_rlwe = (a_bits, b_bits): a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    pub bits_rlwe: RlweCiphertextVector<F>,
    /// bits_rlwe_ntt: ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlweCiphertextVector<F>,
    /// bits_rgsw_c_ntt: the ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlweCiphertextVector<F>,
    /// bits_rgsw_f_ntt: the ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlweCiphertextVector<F>,
    /// output_rlwe_ntt: store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweCiphertext<F>,
    // output_rlwe: store the output ciphertext (g, h) in the coefficient-form
    // pub output_rlwe: RlweCiphertext<F>,
}

/// Evaluation of RlweMultRgsw at the same random point
pub struct ExternalProductEval<F: Field> {
    /// length of bits when decomposing bits
    pub bits_len: usize,
    /// rlwe = (a, b): store the input ciphertext (a, b) where a and b are two polynomials represented by N coefficients.
    pub input_rlwe: RlweEval<F>,
    /// bits_rlwe = (a_bits, b_bits): a_bits (b_bits) corresponds to the bit decomposition result of a (b) in the input rlwe ciphertext
    pub bits_rlwe: RlwesEval<F>,
    /// bits_rlwe_ntt: ntt form of the above bit decomposition result
    pub bits_rlwe_ntt: RlwesEval<F>,
    /// bits_rgsw_c_ntt: the ntt form of the first part (c) in the RGSW ciphertext
    pub bits_rgsw_c_ntt: RlwesEval<F>,
    /// bits_rgsw_f_ntt: the ntt form of the second part (f) in the RGSW ciphertext
    pub bits_rgsw_f_ntt: RlwesEval<F>,
    /// output_rlwe_ntt: store the output ciphertext (g', h') in the NTT-form
    pub output_rlwe_ntt: RlweEval<F>,
}

/// Evaluation of RlweCiphertext at the same random point
pub type RlweEval<F> = (F, F);
/// Evaluation of RlweCiphertexts at the same random point
pub type RlwesEval<F> = (Vec<F>, Vec<F>);

/// store the information used to verify
#[derive(Clone)]
pub struct ExternalProductInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// information of ntt instance
    pub ntt_info: BatchNTTInstanceInfo<F>,
    /// information of bit decomposition
    pub bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for ExternalProductInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "An instance of RLWE * RGSW: #vars = {}", self.num_vars)?;
        write!(f, "- containing ")?;
        self.bits_info.fmt(f)?;
        write!(f, "\n- containing")?;
        self.ntt_info.fmt(f)
    }
}

impl<F: Field> ExternalProductInfo<F> {
    /// Convert to EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> ExternalProductInfo<EF> {
        ExternalProductInfo::<EF> {
            num_vars: self.num_vars,
            ntt_info: self.ntt_info.to_ef::<EF>(),
            bits_info: self.bits_info.to_ef::<EF>(),
        }
    }
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

impl<F: Field> RlweCiphertextVector<F> {
    /// Construct an empty rlweciphertexts
    pub fn new(bits_len: usize) -> Self {
        Self {
            a_vector: Vec::with_capacity(bits_len),
            b_vector: Vec::with_capacity(bits_len),
        }
    }

    /// Add a RLWE ciphertext
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
    /// return the len
    pub fn len(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        assert_eq!(self.a_vector.len(), self.b_vector.len());
        self.a_vector.len()
    }

    /// Returns an iterator that iterates over the evaluations over {0,1}^`num_vars`
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
    pub fn info(&self) -> ExternalProductInfo<F> {
        ExternalProductInfo {
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

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
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
    pub fn evaluate(&self, point: &[F]) -> ExternalProductEval<F> {
        ExternalProductEval::<F> {
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
    ) -> ExternalProductEval<EF> {
        ExternalProductEval::<EF> {
            bits_len: self.bits_info.bits_len,
            input_rlwe: self.input_rlwe.evaluate_ext(point),
            bits_rlwe: self.bits_rlwe.evaluate_ext(point),
            bits_rlwe_ntt: self.bits_rlwe_ntt.evaluate_ext(point),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.evaluate_ext(point),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.evaluate_ext(point),
            output_rlwe_ntt: self.output_rlwe_ntt.evaluate_ext(point),
        }
    }

    /// evaluate given the equality function
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> ExternalProductEval<EF> {
        ExternalProductEval::<EF> {
            bits_len: self.bits_info.bits_len,
            input_rlwe: self.input_rlwe.evaluate_ext_opt(point),
            bits_rlwe: self.bits_rlwe.evaluate_ext_opt(point),
            bits_rlwe_ntt: self.bits_rlwe_ntt.evaluate_ext_opt(point),
            bits_rgsw_c_ntt: self.bits_rgsw_c_ntt.evaluate_ext_opt(point),
            bits_rgsw_f_ntt: self.bits_rgsw_f_ntt.evaluate_ext_opt(point),
            output_rlwe_ntt: self.output_rlwe_ntt.evaluate_ext_opt(point),
        }
    }

    /// return the number of ntt instances contained
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

impl<F: Field> ExternalProductEval<F> {
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

impl<F: Field + Serialize> ExternalProductIOP<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(
        trans: &mut Transcript<F>,
        instance: &ExternalProductInstance<F>,
    ) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <BitDecompositionIOP<F>>::num_coins(&instance.bits_info) + 2,
        )
    }

    /// return the number of coins used in sumcheck protocol
    pub fn num_coins(info: &ExternalProductInfo<F>) -> usize {
        <BitDecompositionIOP<F>>::num_coins(&info.bits_info) + 2
    }

    /// Prove RLWE * RGSW
    pub fn prove(instance: &ExternalProductInstance<F>) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        let randomness = Self::sample_coins(&mut trans, instance);
        let randomness_ntt = <NTTIOP<F>>::sample_coins(&mut trans, &instance.ntt_info.to_clean());

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        // add sumcheck products (without NTT) into poly
        Self::prepare_products_of_polynomial(&randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck products of NTT into poly
        let ntt_instance = instance.extract_ntt_instance(&randomness_ntt);
        NTTBareIOP::<F>::prepare_products_of_polynomial(
            F::one(),
            &mut poly,
            &mut claimed_sum,
            &ntt_instance,
            &u,
            BitsOrder::Normal,
        );

        // prove all sumcheck protocol into a large random sumcheck
        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof = <NTTIOP<F>>::prove_recursion(
            &mut trans,
            &state.randomness,
            &ntt_instance.info(),
            &u,
            BitsOrder::Normal,
        );

        (
            SumcheckKit {
                proof,
                claimed_sum,
                info: poly.info(),
                u,
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
        let bits_instance = instance.extract_decomposed_bits();
        let bits_r_num = <BitDecompositionIOP<F>>::num_coins(&instance.bits_info);
        let (r_bits, r) = randomness.split_at(bits_r_num);
        BitDecompositionIOP::prepare_products_of_polynomial(r_bits, poly, &bits_instance, eq_at_u);

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
            let prod1 = [Rc::new(a.clone()), Rc::new(c.clone()), eq_at_u.clone()];
            let prod2 = [Rc::new(b.clone()), Rc::new(f.clone()), eq_at_u.clone()];
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

    /// Verify RLWE * RGSW
    #[inline]
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &ExternalProductEval<F>,
        evals_at_u: &ExternalProductEval<F>,
        info: &ExternalProductInfo<F>,
        recursive_proof: &NTTRecursiveProof<F>,
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
        let randomness_ntt = trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<F>>::num_coins(&info.ntt_info.to_clean()),
        );

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);

        // check the sumcheck evaluation (without NTT)
        if !Self::verify_subclaim(&randomness, &mut subclaim, evals_at_r, info, eq_at_u_r) {
            return false;
        }

        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        // one is to evaluate the random linear combination of evaluations at point r returned from sumcheck protocol
        let mut ntt_coeff_evals_at_r = F::zero();
        evals_at_r.update_ntt_instance_coeff(&mut ntt_coeff_evals_at_r, &randomness_ntt);
        // the other is to evaluate the random linear combination of evaluations at point u sampled before the sumcheck protocol
        let mut ntt_point_evals_at_u = F::zero();
        evals_at_u.update_ntt_instance_point(&mut ntt_point_evals_at_u, &randomness_ntt);

        if !<NTTBareIOP<F>>::verify_subclaim(
            F::one(),
            &mut subclaim,
            &mut wrapper.claimed_sum,
            ntt_coeff_evals_at_r,
            ntt_point_evals_at_u,
            f_delegation,
        ) {
            return false;
        }

        if !(subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()) {
            return false;
        }
        <NTTIOP<F>>::verify_recursion(
            &mut trans,
            recursive_proof,
            &info.ntt_info,
            &u,
            &subclaim,
            BitsOrder::Normal,
        )
    }

    /// Verify RLWE * RGSW with leaving NTT part outside of the interface
    #[inline]
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &ExternalProductEval<F>,
        info: &ExternalProductInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        // 1. check the bit decomposition part
        let bits_eval = evals.extract_decomposed_bits();
        let bits_r_num = <BitDecompositionIOP<F>>::num_coins(&info.bits_info);
        let (r_ntt, r) = randomness.split_at(bits_r_num);
        let check_decomposed_bits = <BitDecompositionIOP<F>>::verify_subclaim(
            r_ntt,
            subclaim,
            &bits_eval,
            &info.bits_info,
            eq_at_u_r,
        );
        if !check_decomposed_bits {
            return false;
        }

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

impl<F, EF> ExternalProductSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &ExternalProductInstance<F>, code_spec: &S)
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
        let mut claimed_sum = EF::zero();
        let randomness = ExternalProductIOP::sample_coins(&mut prover_trans, &instance_ef);
        let randomness_ntt =
            <NTTIOP<EF>>::sample_coins(&mut prover_trans, &instance_info.ntt_info.to_clean());
        ExternalProductIOP::<EF>::prepare_products_of_polynomial(
            &randomness,
            &mut sumcheck_poly,
            &instance_ef,
            &eq_at_u,
        );

        // 2.? Prover extract the random ntt instance from all ntt instances
        let ntt_instance = instance.extract_ntt_instance_to_ef::<EF>(&randomness_ntt);
        <NTTBareIOP<EF>>::prepare_products_of_polynomial(
            EF::one(),
            &mut sumcheck_poly,
            &mut claimed_sum,
            &ntt_instance,
            &prover_u,
            BitsOrder::Normal,
        );
        let poly_info = sumcheck_poly.info();
        let ntt_instance_info = ntt_instance.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();

        // 2.? [one more step] Prover recursive prove the evaluation of F(u, v)
        let recursive_proof = <NTTIOP<EF>>::prove_recursion(
            &mut prover_trans,
            &sumcheck_state.randomness,
            &ntt_instance_info,
            &prover_u,
            BitsOrder::Normal,
        );
        iop_proof_size += bincode::serialize(&recursive_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        // let evals_at_r = instance.evaluate_ext(&sumcheck_state.randomness);
        // let evals_at_u = instance.evaluate_ext(&prover_u);
        let eq_at_r = gen_identity_evaluations(&sumcheck_state.randomness);
        let evals_at_r = instance.evaluate_ext_opt(&eq_at_r);
        let evals_at_u = instance.evaluate_ext_opt(eq_at_u.as_ref());

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = sumcheck_state.randomness.clone();
        let mut requested_point_at_u = prover_u.clone();
        let oracle_randomness = prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        );
        requested_point_at_r.extend(&oracle_randomness);
        requested_point_at_u.extend(&oracle_randomness);
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
            <ExternalProductIOP<EF>>::num_coins(&instance_info),
        );
        let randomness_ntt = verifier_trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<EF>>::num_coins(&instance_info.ntt_info.to_clean()),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the sumcheck proof generated in RLWE * RGSW");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subclaim = ExternalProductIOP::<EF>::verify_subclaim(
            &randomness,
            &mut subclaim,
            &evals_at_r,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subclaim);

        // 3.? Check the NTT part
        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        // one is to evaluate the random linear combination of evaluations at point r returned from sumcheck protocol
        let mut ntt_coeff_evals_at_r = EF::zero();
        evals_at_r.update_ntt_instance_coeff(&mut ntt_coeff_evals_at_r, &randomness_ntt);
        // the other is to evaluate the random linear combination of evaluations at point u sampled before the sumcheck protocol
        let mut ntt_point_evals_at_u = EF::zero();
        evals_at_u.update_ntt_instance_point(&mut ntt_point_evals_at_u, &randomness_ntt);

        // check the sumcheck part of NTT
        let check_ntt_bare = <NTTBareIOP<EF>>::verify_subclaim(
            EF::one(),
            &mut subclaim,
            &mut claimed_sum,
            ntt_coeff_evals_at_r,
            ntt_point_evals_at_u,
            f_delegation,
        );
        assert!(check_ntt_bare);
        assert_eq!(subclaim.expected_evaluations, EF::zero());
        assert_eq!(claimed_sum, EF::zero());
        // check the recursive part of NTT
        let check_recursive = <NTTIOP<EF>>::verify_recursion(
            &mut verifier_trans,
            &recursive_proof,
            &ntt_instance_info,
            &verifier_u,
            &subclaim,
            BitsOrder::Normal,
        );
        assert!(check_recursive);

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals_at_r = evals_at_r.flatten();
        let flatten_evals_at_u = evals_at_u.flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals_at_r.log_num_oracles(),
        );
        let check_oracle_at_r =
            verify_oracle_relation(&flatten_evals_at_r, oracle_eval_at_r, &oracle_randomness);
        let check_oracle_at_u =
            verify_oracle_relation(&flatten_evals_at_u, oracle_eval_at_u, &oracle_randomness);
        assert!(check_oracle_at_r && check_oracle_at_u);
        let iop_verifier_time = verifier_start.elapsed().as_millis();

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

impl<F: Field + Serialize> ExternalProductIOPPure<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>) -> Vec<F> {
        trans.get_vec_challenge(b"randomness to combine sumcheck protocols", 2)
    }

    /// return the number of coins used in sumcheck protocol
    pub fn num_coins() -> usize {
        2
    }

    /// Prove RLWE * RGSW
    pub fn prove(instance: &ExternalProductInstance<F>) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        let randomness = Self::sample_coins(&mut trans);
        let randomness_ntt = <NTTIOP<F>>::sample_coins(&mut trans, &instance.ntt_info.to_clean());

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        // add sumcheck products (without NTT) into poly
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck products of NTT into poly
        let ntt_instance = instance.extract_ntt_instance(&randomness_ntt);
        <NTTBareIOP<F>>::prepare_products_of_polynomial(
            F::one(),
            &mut poly,
            &mut claimed_sum,
            &ntt_instance,
            &u,
            BitsOrder::Normal,
        );

        // prove all sumcheck protocol into a large random sumcheck
        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof = <NTTIOP<F>>::prove_recursion(
            &mut trans,
            &state.randomness,
            &ntt_instance.info(),
            &u,
            BitsOrder::Normal,
        );

        (
            SumcheckKit {
                proof,
                claimed_sum,
                info: poly.info(),
                u,
                randomness: state.randomness,
            },
            recursive_proof,
        )
    }

    /// Prove RLWE * RGSW with leaving the NTT part outside this interface
    #[inline]
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &ExternalProductInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        // let bits_instance = instance.extract_decomposed_bits();
        // let bits_r_num = <BitDecomposition<F>>::num_coins(&instance.bits_info);
        // let (r_bits, r) = randomness.split_at(bits_r_num);
        // BitDecomposition::prove_as_subprotocol(r_bits, poly, &bits_instance, eq_at_u);

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

    /// Verify RLWE * RGSW
    #[inline]
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &ExternalProductEval<F>,
        evals_at_u: &ExternalProductEval<F>,
        info: &ExternalProductInfo<F>,
        recursive_proof: &NTTRecursiveProof<F>,
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
        let randomness_ntt = trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<F>>::num_coins(&info.ntt_info.to_clean()),
        );

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);

        // check the sumcheck evaluation (without NTT)
        if !Self::verify_as_subprotocol(&randomness, &mut subclaim, evals_at_r, info, eq_at_u_r) {
            return false;
        }

        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        // one is to evaluate the random linear combination of evaluations at point r returned from sumcheck protocol
        let mut ntt_coeff_evals_at_r = F::zero();
        evals_at_r.update_ntt_instance_coeff(&mut ntt_coeff_evals_at_r, &randomness_ntt);
        // the other is to evaluate the random linear combination of evaluations at point u sampled before the sumcheck protocol
        let mut ntt_point_evals_at_u = F::zero();
        evals_at_u.update_ntt_instance_point(&mut ntt_point_evals_at_u, &randomness_ntt);

        if !<NTTBareIOP<F>>::verify_subclaim(
            F::one(),
            &mut subclaim,
            &mut wrapper.claimed_sum,
            ntt_coeff_evals_at_r,
            ntt_point_evals_at_u,
            f_delegation,
        ) {
            return false;
        }

        if !(subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()) {
            return false;
        }
        <NTTIOP<F>>::verify_recursion(
            &mut trans,
            recursive_proof,
            &info.ntt_info,
            &u,
            &subclaim,
            BitsOrder::Normal,
        )
    }

    /// Verify RLWE * RGSW with leaving NTT part outside of the interface
    #[inline]
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &ExternalProductEval<F>,
        info: &ExternalProductInfo<F>,
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

impl<F, EF> ExternalProductSnarksOpt<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &ExternalProductInstance<F>, code_spec: &S, block_size: usize)
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

        // --- Lookup Part ---
        let mut lookup_instance = instance_ef.extract_lookup_instance(block_size);
        let lookup_info = lookup_instance.info();
        println!("- containing {lookup_info}\n");
        // random value to initiate lookup
        let random_value =
            prover_trans.get_challenge(b"random point used to generate the second oracle");
        lookup_instance.generate_h_vec(random_value);
        // --------------------

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let mut claimed_sum = EF::zero();
        let randomness = ExternalProductIOPPure::sample_coins(&mut prover_trans);
        let randomness_ntt =
            <NTTIOP<EF>>::sample_coins(&mut prover_trans, &instance_info.ntt_info.to_clean());
        ExternalProductIOPPure::<EF>::prove_as_subprotocol(
            &randomness,
            &mut sumcheck_poly,
            &instance_ef,
            &eq_at_u,
        );

        // 2.? Prover extract the random ntt instance from all ntt instances
        let ntt_instance = instance.extract_ntt_instance_to_ef::<EF>(&randomness_ntt);
        <NTTBareIOP<EF>>::prepare_products_of_polynomial(
            EF::one(),
            &mut sumcheck_poly,
            &mut claimed_sum,
            &ntt_instance,
            &prover_u,
            BitsOrder::Normal,
        );
        let ntt_instance_info = ntt_instance.info();

        // --- Lookup Part ---
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
        // --------------------

        let poly_info = sumcheck_poly.info();
        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();

        // 2.? [one more step] Prover recursive prove the evaluation of F(u, v)
        let recursive_proof = <NTTIOP<EF>>::prove_recursion(
            &mut prover_trans,
            &sumcheck_state.randomness,
            &ntt_instance_info,
            &prover_u,
            BitsOrder::Normal,
        );
        iop_proof_size += bincode::serialize(&recursive_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        // let evals_at_r = instance.evaluate_ext(&sumcheck_state.randomness);
        // let evals_at_u = instance.evaluate_ext(&prover_u);
        let eq_at_r = gen_identity_evaluations(&sumcheck_state.randomness);
        let evals_at_r = instance.evaluate_ext_opt(&eq_at_r);
        let evals_at_u = instance.evaluate_ext_opt(eq_at_u.as_ref());

        // --- Lookup Part ---
        let lookup_evals = lookup_instance.evaluate(&sumcheck_state.randomness);
        // -------------------

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = sumcheck_state.randomness.clone();
        let mut requested_point_at_u = prover_u.clone();
        let oracle_randomness = prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        );
        requested_point_at_r.extend(&oracle_randomness);
        requested_point_at_u.extend(&oracle_randomness);
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

        // --- Lookup Part ---
        let random_value =
            verifier_trans.get_challenge(b"random point used to generate the second oracle");
        // -------------------

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <ExternalProductIOPPure<EF>>::num_coins(),
        );
        let randomness_ntt = verifier_trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<EF>>::num_coins(&instance_info.ntt_info.to_clean()),
        );

        // --- Lookup Part ---
        let mut lookup_randomness = verifier_trans.get_vec_challenge(
            b"Lookup IOP: randomness to combine sumcheck protocols",
            <LookupIOP<EF>>::num_coins(&lookup_info),
        );
        lookup_randomness.push(random_value);
        // -------------------

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the sumcheck proof generated in RLWE * RGSW");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subclaim = ExternalProductIOPPure::<EF>::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &evals_at_r,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subclaim);

        // 3.? Check the NTT part
        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        // one is to evaluate the random linear combination of evaluations at point r returned from sumcheck protocol
        let mut ntt_coeff_evals_at_r = EF::zero();
        evals_at_r.update_ntt_instance_coeff(&mut ntt_coeff_evals_at_r, &randomness_ntt);
        // the other is to evaluate the random linear combination of evaluations at point u sampled before the sumcheck protocol
        let mut ntt_point_evals_at_u = EF::zero();
        evals_at_u.update_ntt_instance_point(&mut ntt_point_evals_at_u, &randomness_ntt);

        // check the sumcheck part of NTT
        let check_ntt_bare = <NTTBareIOP<EF>>::verify_subclaim(
            EF::one(),
            &mut subclaim,
            &mut claimed_sum,
            ntt_coeff_evals_at_r,
            ntt_point_evals_at_u,
            f_delegation,
        );
        assert!(check_ntt_bare);

        // --- Lookup Part ---
        let check_lookup = LookupIOP::<EF>::verify_subclaim(
            &lookup_randomness,
            &mut subclaim,
            &lookup_evals,
            &lookup_info,
            eq_at_u_r,
        );
        assert!(check_lookup);
        // -------------------

        assert_eq!(subclaim.expected_evaluations, EF::zero());
        assert_eq!(claimed_sum, EF::zero());
        // check the recursive part of NTT
        let check_recursive = <NTTIOP<EF>>::verify_recursion(
            &mut verifier_trans,
            &recursive_proof,
            &ntt_instance_info,
            &verifier_u,
            &subclaim,
            BitsOrder::Normal,
        );
        assert!(check_recursive);

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals_at_r = evals_at_r.flatten();
        let flatten_evals_at_u = evals_at_u.flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals_at_r.log_num_oracles(),
        );
        let check_oracle_at_r =
            verify_oracle_relation(&flatten_evals_at_r, oracle_eval_at_r, &oracle_randomness);
        let check_oracle_at_u =
            verify_oracle_relation(&flatten_evals_at_u, oracle_eval_at_u, &oracle_randomness);
        assert!(check_oracle_at_r && check_oracle_at_u);
        let iop_verifier_time = verifier_start.elapsed().as_millis();

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

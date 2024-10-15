//! IOP for Accumulator updating t times
//! ACC = ACC + (X^{-a_u} - 1) * ACC * RGSW(Z_u)
//! Each updation contains two single ntt operations and one multiplication between RLWE and RGSW
use crate::piop::LookupIOP;
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::MLSumcheck;
use crate::sumcheck::ProofWrapper;
use crate::sumcheck::SumcheckKit;
use core::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use super::ntt::NTTRecursiveProof;
use super::rlwe_mul_rgsw::RlweEval;
use super::rlwe_mul_rgsw::RlweMultRgswEval;
use super::rlwe_mul_rgsw::RlweMultRgswInfo;
use super::BitDecompositionInstance;
use super::LookupInstance;
use super::NTTBareIOP;
use super::RlweCiphertext;
use super::RlweMultRgswIOP;
use super::RlweMultRgswIOPPure;
use super::RlweMultRgswInstance;
use super::{BatchNTTInstanceInfo, BitDecompositionInstanceInfo, NTTInstance, NTTIOP};
use crate::utils::{
    add_assign_ef, eval_identity_function, gen_identity_evaluations, print_statistic,
    verify_oracle_relation,
};
use algebra::utils::Transcript;
use algebra::AbstractExtensionField;
use algebra::{DenseMultilinearExtension, Field, ListOfProductsOfPolynomials};
use itertools::izip;
use itertools::Itertools;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};

/// IOP for Accumulator
pub struct AccumulatorIOP<F: Field>(PhantomData<F>);

/// SNARKs for Accumulator compiled with PCS
pub struct AccumulatorSnarks<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);

/// IOP for Accumulator
pub struct AccumulatorIOPPure<F: Field>(PhantomData<F>);

/// SNARKs for Accumulator compiled with PCS
pub struct AccumulatorSnarksOpt<F: Field, EF: AbstractExtensionField<F>>(
    PhantomData<F>,
    PhantomData<EF>,
);
/// accumulator witness when performing ACC = ACC + (X^{-a_u} + 1) * ACC * RGSW(Z_u)
#[derive(Debug, Clone)]
pub struct AccumulatorWitness<F: Field> {
    /// * Witness when performing input_rlwe_ntt := (X^{-a_u} + 1) * ACC
    ///
    /// ACC of ntt form
    pub acc_ntt: RlweCiphertext<F>,
    /// scalar d = (X^{-a_u} + 1) of coefficient form
    pub d: DenseMultilinearExtension<F>,
    /// scalar d = (X^{-a_u} + 1) of ntt form
    pub d_ntt: DenseMultilinearExtension<F>,
    /// result d * ACC of ntt form
    pub input_rlwe_ntt: RlweCiphertext<F>,
    /// * Witness when performing output_rlwe_ntt := input_rlwe * RGSW(Z_u) where input_rlwe = (X^{-a_u} + 1) * ACC
    ///
    /// result of RLWE * RGSW
    pub rlwe_mult_rgsw: RlweMultRgswInstance<F>,
}

/// Evaluation of AccumulatorWitnessEval at the same random point
pub struct AccumulatorWitnessEval<F: Field> {
    /// ACC of ntt form
    pub acc_ntt: RlweEval<F>,
    /// scalar d = (X^{-a_u} + 1) of coefficient form
    pub d: F,
    /// scalar d = (X^{-a_u} + 1) of ntt form
    pub d_ntt: F,
    /// result d * ACC = RLWE of ntt form
    pub input_rlwe_ntt: RlweEval<F>,
    /// result of RLWE * RGSW
    pub rlwe_mult_rgsw: RlweMultRgswEval<F>,
}

/// Store the ntt instance, bit decomposition instance, and the sumcheck instance for an Accumulator updating `t` times
pub struct AccumulatorInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// number of updations in Accumulator denoted by t
    pub num_updations: usize,
    /// input of the Accumulator, represented in coefficient form
    pub input: RlweCiphertext<F>,
    /// input of the Accumulator, represented in NTT form
    // pub input_ntt: RlweCiphertext<F>,
    /// witnesses stored in updations
    pub updations: Vec<AccumulatorWitness<F>>,
    /// output of the Accumulator, represented in NTT form
    pub output_ntt: RlweCiphertext<F>,
    /// output of the Accumulator, represented in coefficient form
    pub output: RlweCiphertext<F>,
    /// info for RLWE * RGSW
    pub mult_info: RlweMultRgswInfo<F>,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// info for NTT
    pub ntt_info: BatchNTTInstanceInfo<F>,
}

/// Evaluation of AccumulatorInstance at the same random point
pub struct AccumulatorEval<F: Field> {
    /// input of the Accumulator, represented in coefficient form
    pub input: RlweEval<F>,
    /// witnesses stored in updations
    pub updations: Vec<AccumulatorWitnessEval<F>>,
    /// output of the Accumulator, represented in NTT form
    pub output_ntt: RlweEval<F>,
    /// output of the Accumulator, represented in coefficient form
    pub output: RlweEval<F>,
}

/// Store the Accumulator info used to verify
pub struct AccumulatorInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// number of updations in Accumulator denoted by t
    pub num_updations: usize,
    /// info for RLWE * RGSW
    pub mult_info: RlweMultRgswInfo<F>,
    /// info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// info for NTT
    pub ntt_info: BatchNTTInstanceInfo<F>,
}

impl<F: Field> fmt::Display for AccumulatorInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "An instance of Accumulator: #vars = {}", self.num_vars)?;
        write!(f, "- containing ")?;
        self.bits_info.fmt(f)?;
        write!(f, "\n- containing")?;
        self.ntt_info.fmt(f)
    }
}

impl<F: Field> AccumulatorWitness<F> {
    /// Return the output_ntt
    #[inline]
    pub fn get_output(&self) -> RlweCiphertext<F> {
        self.rlwe_mult_rgsw.output_rlwe_ntt.clone()
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.rlwe_mult_rgsw.num_oracles()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Return the number of ntt contained in this instance
    #[inline]
    pub fn num_ntt_contained(&self) -> usize {
        self.rlwe_mult_rgsw.num_ntt_contained() + 3
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros
    #[inline]
    pub fn pack_all_mles(&self) -> Vec<F> {
        let mut res = self
            .d
            .iter()
            .chain(self.d_ntt.iter())
            .copied()
            .collect::<Vec<F>>();
        res.append(&mut self.acc_ntt.pack_all_mles());
        res.append(&mut self.input_rlwe_ntt.pack_all_mles());
        res.append(&mut self.rlwe_mult_rgsw.pack_all_mles());
        res
    }

    /// Convert to EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> AccumulatorWitness<EF> {
        AccumulatorWitness::<EF> {
            acc_ntt: self.acc_ntt.to_ef::<EF>(),
            d: self.d.to_ef::<EF>(),
            d_ntt: self.d_ntt.to_ef::<EF>(),
            input_rlwe_ntt: self.input_rlwe_ntt.to_ef::<EF>(),
            rlwe_mult_rgsw: self.rlwe_mult_rgsw.to_ef::<EF>(),
        }
    }

    /// Evaluate at the same random point defined over F
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> AccumulatorWitnessEval<F> {
        AccumulatorWitnessEval {
            acc_ntt: self.acc_ntt.evaluate(point),
            d: self.d.evaluate(point),
            d_ntt: self.d_ntt.evaluate(point),
            input_rlwe_ntt: self.input_rlwe_ntt.evaluate(point),
            rlwe_mult_rgsw: self.rlwe_mult_rgsw.evaluate(point),
        }
    }
    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> AccumulatorWitnessEval<EF> {
        AccumulatorWitnessEval {
            acc_ntt: self.acc_ntt.evaluate_ext(point),
            d: self.d.evaluate_ext(point),
            d_ntt: self.d_ntt.evaluate_ext(point),
            input_rlwe_ntt: self.input_rlwe_ntt.evaluate_ext(point),
            rlwe_mult_rgsw: self.rlwe_mult_rgsw.evaluate_ext(point),
        }
    }

    /// update the ntt instance to be proved
    #[inline]
    pub fn update_ntt_instance(
        &self,
        r_coeffs: &mut DenseMultilinearExtension<F>,
        r_points: &mut DenseMultilinearExtension<F>,
        randomness: &[F],
    ) {
        assert_eq!(randomness.len(), self.num_ntt_contained());
        // d ==NTT== d_ntt
        let (r_used, r) = randomness.split_at(3);
        *r_coeffs += (r_used[0], &self.d);
        *r_points += (r_used[0], &self.d_ntt);
        // input_rlwe ==NTT== input_rlwe_ntt
        *r_coeffs += (r_used[1], &self.rlwe_mult_rgsw.input_rlwe.a);
        *r_points += (r_used[1], &self.input_rlwe_ntt.a);
        *r_coeffs += (r_used[2], &self.rlwe_mult_rgsw.input_rlwe.b);
        *r_points += (r_used[2], &self.input_rlwe_ntt.b);

        self.rlwe_mult_rgsw
            .update_ntt_instance(r_coeffs, r_points, r);
    }

    /// update the ntt instance to be proved
    #[inline]
    pub fn update_ntt_instance_to_ef<EF: AbstractExtensionField<F>>(
        &self,
        r_coeffs: &mut DenseMultilinearExtension<EF>,
        r_points: &mut DenseMultilinearExtension<EF>,
        randomness: &[EF],
    ) {
        assert_eq!(randomness.len(), self.num_ntt_contained());
        // d ==NTT== d_ntt
        let (r_used, r) = randomness.split_at(3);
        add_assign_ef(r_coeffs, &r_used[0], &self.d);
        add_assign_ef(r_points, &r_used[0], &self.d_ntt);

        // input_rlwe ==NTT== input_rlwe_ntt
        add_assign_ef(r_coeffs, &r_used[1], &self.rlwe_mult_rgsw.input_rlwe.a);
        add_assign_ef(r_points, &r_used[1], &self.input_rlwe_ntt.a);
        add_assign_ef(r_coeffs, &r_used[2], &self.rlwe_mult_rgsw.input_rlwe.b);
        add_assign_ef(r_points, &r_used[2], &self.input_rlwe_ntt.b);

        self.rlwe_mult_rgsw
            .update_ntt_instance_to_ef::<EF>(r_coeffs, r_points, r);
    }
}

impl<F: Field> AccumulatorInstance<F> {
    /// construct an accumulator instance based on ntt info and bit-decomposition info
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        num_vars: usize,
        num_updations: usize,
        input: RlweCiphertext<F>,
        updations: Vec<AccumulatorWitness<F>>,
        output_ntt: RlweCiphertext<F>,
        output: RlweCiphertext<F>,
        bits_info: &BitDecompositionInstanceInfo<F>,
        ntt_info: &BatchNTTInstanceInfo<F>,
    ) -> Self {
        let ntt_info = BatchNTTInstanceInfo::<F> {
            num_ntt: 4 + num_updations * updations[0].num_ntt_contained(),
            num_vars,
            ntt_table: Arc::clone(&ntt_info.ntt_table),
        };

        let bits_info = BitDecompositionInstanceInfo::<F> {
            num_vars,
            base: bits_info.base,
            base_len: bits_info.base_len,
            bits_len: bits_info.bits_len,
            num_instances: 2 * num_updations,
        };

        assert!(num_updations > 0);
        let mult_info = updations[0].rlwe_mult_rgsw.info();
        assert_eq!(num_updations, updations.len());
        Self {
            num_vars,
            num_updations,
            input,
            updations,
            output,
            output_ntt,
            mult_info,
            ntt_info,
            bits_info,
        }
    }

    /// Extract the information
    #[inline]
    pub fn info(&self) -> AccumulatorInstanceInfo<F> {
        AccumulatorInstanceInfo {
            num_vars: self.num_vars,
            num_updations: self.num_updations,
            mult_info: self.mult_info.clone(),
            bits_info: self.bits_info.clone(),
            ntt_info: self.ntt_info.clone(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.num_updations * self.updations[0].num_oracles()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Return the number of NTT instances contained
    #[inline]
    pub fn num_ntt_contained(&self) -> usize {
        4 + self.num_updations * self.updations[0].num_ntt_contained()
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_all_mles(&self) -> Vec<F> {
        let mut res = Vec::new();
        res.append(&mut self.input.pack_all_mles());
        res.append(&mut self.output_ntt.pack_all_mles());
        res.append(&mut self.output.pack_all_mles());
        for updation in &self.updations {
            res.append(&mut updation.pack_all_mles());
        }
        res
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    #[inline]
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars_added = self.log_num_oracles();
        let num_vars = self.num_vars + num_vars_added;
        let num_zeros_padded = ((1 << num_vars_added) - self.num_oracles()) * (1 << self.num_vars);

        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> AccumulatorInstance<EF> {
        AccumulatorInstance::<EF> {
            num_vars: self.num_vars,
            num_updations: self.num_updations,
            input: self.input.to_ef::<EF>(),
            updations: self
                .updations
                .iter()
                .map(|updation| updation.to_ef::<EF>())
                .collect(),
            output_ntt: self.output_ntt.to_ef::<EF>(),
            output: self.output.to_ef::<EF>(),
            mult_info: self.mult_info.to_ef::<EF>(),
            bits_info: self.bits_info.to_ef::<EF>(),
            ntt_info: self.ntt_info.to_ef::<EF>(),
        }
    }

    /// Evaluate at the same random point
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> AccumulatorEval<F> {
        AccumulatorEval::<F> {
            input: self.input.evaluate(point),
            output_ntt: self.output_ntt.evaluate(point),
            output: self.output.evaluate(point),
            updations: self
                .updations
                .iter()
                .map(|updation| updation.evaluate(point))
                .collect(),
        }
    }

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(&self, point: &[EF]) -> AccumulatorEval<EF> {
        AccumulatorEval::<EF> {
            input: self.input.evaluate_ext(point),
            output_ntt: self.output_ntt.evaluate_ext(point),
            output: self.output.evaluate_ext(point),
            updations: self
                .updations
                .par_iter()
                .map(|updation| updation.evaluate_ext(point))
                .collect(),
        }
    }

    /// Extract all ntt instances contained into a single random NTT instance
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

        let (r_used, r) = randomness.split_at(4);
        // input ==NTT== input_ntt
        let input_ntt = &self.updations[0].acc_ntt;
        random_coeffs += (r_used[0], &self.input.a);
        random_points += (r_used[0], &input_ntt.a);
        random_coeffs += (r_used[1], &self.input.b);
        random_points += (r_used[1], &input_ntt.b);

        // output_ntt ==NTT== output
        random_coeffs += (r_used[2], &self.output.a);
        random_points += (r_used[2], &self.output_ntt.a);
        random_coeffs += (r_used[3], &self.output.b);
        random_points += (r_used[3], &self.output_ntt.b);

        let r_each_num = self.updations[0].num_ntt_contained();
        // ntts in each accumulator
        for (updation, r_each) in izip!(&self.updations, r.chunks_exact(r_each_num)) {
            updation.update_ntt_instance(&mut random_coeffs, &mut random_points, r_each);
        }

        NTTInstance::<F> {
            num_vars: self.num_vars,
            ntt_table: self.ntt_info.ntt_table.clone(),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Extract all ntt instances contained into a single random NTT instance
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

        let (r_used, r) = randomness.split_at(4);
        // input ==NTT== input_ntt
        let input_ntt = &self.updations[0].acc_ntt;
        add_assign_ef(&mut random_coeffs, &r_used[0], &self.input.a);
        add_assign_ef(&mut random_points, &r_used[0], &input_ntt.a);
        add_assign_ef(&mut random_coeffs, &r_used[1], &self.input.b);
        add_assign_ef(&mut random_points, &r_used[1], &input_ntt.b);

        // output_ntt ==NTT== output
        add_assign_ef(&mut random_coeffs, &r_used[2], &self.output.a);
        add_assign_ef(&mut random_points, &r_used[2], &self.output_ntt.a);
        add_assign_ef(&mut random_coeffs, &r_used[3], &self.output.b);
        add_assign_ef(&mut random_points, &r_used[3], &self.output_ntt.b);

        let r_each_num = self.updations[0].num_ntt_contained();
        // ntts in each accumulator
        for (updation, r_each) in izip!(&self.updations, r.chunks_exact(r_each_num)) {
            updation.update_ntt_instance_to_ef::<EF>(
                &mut random_coeffs,
                &mut random_points,
                r_each,
            );
        }

        NTTInstance::<EF> {
            num_vars: self.num_vars,
            ntt_table: Arc::new(
                self.ntt_info
                    .ntt_table
                    .iter()
                    .map(|x| EF::from_base(*x))
                    .collect::<Vec<EF>>(),
            ),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Extract all decomposed bits
    #[inline]
    pub fn extract_decomposed_bits(&self) -> BitDecompositionInstance<F> {
        let mut res = BitDecompositionInstance {
            base: self.bits_info.base,
            base_len: self.bits_info.base_len,
            bits_len: self.bits_info.bits_len,
            num_vars: self.num_vars,
            d_val: Vec::with_capacity(2 * self.num_updations),
            d_bits: Vec::with_capacity(2 * self.bits_info.bits_len * self.num_updations),
        };
        for updation in &self.updations {
            updation.rlwe_mult_rgsw.update_decomposed_bits(&mut res);
        }
        res
    }

    /// Extract lookup instance
    #[inline]
    pub fn extract_lookup_instance(&self, block_size: usize) -> LookupInstance<F> {
        self.extract_decomposed_bits()
            .extract_lookup_instance(block_size)
    }
}

impl<F: Field> AccumulatorWitnessEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.rlwe_mult_rgsw.num_oracles()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Flatten the evaluations into a Vector
    #[inline]
    pub fn flatten(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.num_oracles());
        res.push(self.d);
        res.push(self.d_ntt);
        res.push(self.acc_ntt.0);
        res.push(self.acc_ntt.1);
        res.push(self.input_rlwe_ntt.0);
        res.push(self.input_rlwe_ntt.1);
        res.append(&mut self.rlwe_mult_rgsw.flatten());
        res
    }

    /// Update the coefficients of the random NTT instance to be proved
    #[inline]
    pub fn update_ntt_instance_coeff(&self, r_coeff: &mut F, randomness: &[F]) {
        let (r_used, r) = randomness.split_at(3);
        *r_coeff += r_used[0] * self.d;
        *r_coeff += r_used[1] * self.rlwe_mult_rgsw.input_rlwe.0;
        *r_coeff += r_used[2] * self.rlwe_mult_rgsw.input_rlwe.1;

        self.rlwe_mult_rgsw.update_ntt_instance_coeff(r_coeff, r);
    }

    /// Update the point-values of the random NTT instance to be proved
    #[inline]
    pub fn update_ntt_instance_point(&self, r_point: &mut F, randomness: &[F]) {
        let (r_used, r) = randomness.split_at(3);
        *r_point += r_used[0] * self.d_ntt;
        *r_point += r_used[1] * self.input_rlwe_ntt.0;
        *r_point += r_used[2] * self.input_rlwe_ntt.1;

        self.rlwe_mult_rgsw.update_ntt_instance_point(r_point, r);
    }
}

impl<F: Field> AccumulatorEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.updations.len() * self.updations[0].num_oracles()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Faltten all evaluations into a vector
    #[inline]
    pub fn flatten(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.num_oracles());
        res.push(self.input.0);
        res.push(self.input.1);
        res.push(self.output_ntt.0);
        res.push(self.output_ntt.1);
        res.push(self.output.0);
        res.push(self.output.1);
        for updation in &self.updations {
            res.append(&mut updation.flatten());
        }

        res
    }

    /// Update the coefficient evaluation of the random NTT instance
    #[inline]
    pub fn update_ntt_instance_coeff(&self, r_coeff: &mut F, randomness: &[F]) {
        let (r_used, r) = randomness.split_at(4);
        *r_coeff += r_used[0] * self.input.0;
        *r_coeff += r_used[1] * self.input.1;
        *r_coeff += r_used[2] * self.output.0;
        *r_coeff += r_used[3] * self.output.1;

        let r_each_num = r.len() / self.updations.len();
        for (updation, r_each) in izip!(&self.updations, r.chunks_exact(r_each_num)) {
            updation.update_ntt_instance_coeff(r_coeff, r_each);
        }
    }

    /// Update the point evaluation of the random NTT instance
    #[inline]
    pub fn update_ntt_instance_point(&self, r_point: &mut F, randomness: &[F]) {
        let (r_used, r) = randomness.split_at(4);
        let input_ntt = &self.updations[0].acc_ntt;
        *r_point += r_used[0] * input_ntt.0;
        *r_point += r_used[1] * input_ntt.1;

        *r_point += r_used[2] * self.output_ntt.0;
        *r_point += r_used[3] * self.output_ntt.1;

        let r_each_num = r.len() / self.updations.len();
        for (updation, r_each) in izip!(&self.updations, r.chunks_exact(r_each_num)) {
            updation.update_ntt_instance_point(r_point, r_each);
        }
    }
}

impl<F: Field + Serialize> AccumulatorIOP<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &AccumulatorInstance<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            instance.num_updations
                * (<RlweMultRgswIOP<F>>::num_coins(&instance.updations[0].rlwe_mult_rgsw.info())
                    + 2),
        )
    }

    /// Return the number of random coins used in this IOP
    pub fn num_coins(info: &AccumulatorInstanceInfo<F>) -> usize {
        info.num_updations * (<RlweMultRgswIOP<F>>::num_coins(&info.mult_info) + 2)
    }

    /// Prove accumulator updating `num_updations`` times
    #[inline]
    pub fn prove(instance: &AccumulatorInstance<F>) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut trans = Transcript::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        let randomness = Self::sample_coins(&mut trans, instance);
        let randomness_ntt = <NTTIOP<F>>::sample_coins(&mut trans, &instance.ntt_info);

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        // add sumcheck products (without NTT) into poly
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck_products of NTT into poly
        let ntt_instance = instance.extract_ntt_instance(&randomness_ntt);
        <NTTBareIOP<F>>::prepare_products_of_polynomial(
            F::one(),
            &mut poly,
            &mut claimed_sum,
            &ntt_instance,
            &u,
        );

        // prove all sumcheck protocol into a large random sumcheck
        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof =
            <NTTIOP<F>>::prove_recursion(&mut trans, &state.randomness, &ntt_instance.info(), &u);

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

    /// Verify the accumulator updating `num_updations` times
    #[inline]
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &AccumulatorEval<F>,
        evals_at_u: &AccumulatorEval<F>,
        info: &AccumulatorInstanceInfo<F>,
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
            <NTTIOP<F>>::num_coins(&info.ntt_info),
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
        <NTTIOP<F>>::verify_recursion(&mut trans, recursive_proof, &info.ntt_info, &u, &subclaim)
    }
    /// Prover Accumulator
    #[inline]
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &AccumulatorInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let r_each_num = RlweMultRgswIOP::num_coins(&instance.mult_info) + 2;
        assert_eq!(randomness.len(), instance.num_updations * r_each_num);

        // in other updations, acc_ntt = acc_ntt (in last updation) + output_ntt of RLWE * RGSW
        for (updation, r) in izip!(&instance.updations, randomness.chunks_exact(r_each_num)) {
            let (r, r_mult) = r.split_at(2);
            // When proving ACC = ACC + (x^a_u - 1) * ACC * RGSW
            // step 1. `ACC` * `d` = RLWE
            // sum_x eq(u, x) * (ACC.a(x) * d(x) - a(x)) = 0
            poly.add_product(
                [
                    Rc::new(updation.d_ntt.clone()),
                    Rc::new(updation.acc_ntt.a.clone()),
                    eq_at_u.clone(),
                ],
                r[0],
            );
            poly.add_product(
                [
                    Rc::new(updation.input_rlwe_ntt.a.clone()),
                    Rc::clone(eq_at_u),
                ],
                -r[0],
            );
            // sum_x eq(u, x) * (ACC.b(x) * d(x) - RLWE.b(x)) = 0
            poly.add_product(
                [
                    Rc::new(updation.d_ntt.clone()),
                    Rc::new(updation.acc_ntt.b.clone()),
                    eq_at_u.clone(),
                ],
                r[1],
            );
            poly.add_product(
                [
                    Rc::new(updation.input_rlwe_ntt.b.clone()),
                    Rc::clone(eq_at_u),
                ],
                -r[1],
            );

            // step2: RLWE * RGSW
            <RlweMultRgswIOP<F>>::prove_as_subprotocol(
                r_mult,
                poly,
                &updation.rlwe_mult_rgsw,
                eq_at_u,
            );
        }
    }

    /// Verify the sumcheck part of accumulator updations (not including NTT part)
    #[inline]
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &AccumulatorEval<F>,
        info: &AccumulatorInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        let r_each_num = RlweMultRgswIOP::num_coins(&info.mult_info) + 2;
        assert_eq!(randomness.len(), info.num_updations * r_each_num);

        // check the sumcheck part
        for (updation, r) in izip!(&evals.updations, randomness.chunks_exact(r_each_num)) {
            let (r, r_mult) = r.split_at(2);
            subclaim.expected_evaluations -= eq_at_u_r
                * (r[0] * (updation.d_ntt * updation.acc_ntt.0 - updation.input_rlwe_ntt.0)
                    + r[1] * (updation.d_ntt * updation.acc_ntt.1 - updation.input_rlwe_ntt.1));
            if !RlweMultRgswIOP::verify_as_subprotocol(
                r_mult,
                subclaim,
                &updation.rlwe_mult_rgsw,
                &info.mult_info,
                eq_at_u_r,
            ) {
                return false;
            }
        }

        // check the equality relations among the accmulator updations
        for (this, next) in evals.updations.iter().tuple_windows() {
            let this_acc = &this.acc_ntt;
            let this_mult = &this.rlwe_mult_rgsw.output_rlwe_ntt;
            let next_acc = &next.acc_ntt;
            if !(this_acc.0 + this_mult.0 == next_acc.0 && this_acc.1 + this_mult.1 == next_acc.1) {
                return false;
            }
        }
        true
    }
}

impl<F, EF> AccumulatorSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &AccumulatorInstance<F>, code_spec: &S)
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
        let randomness = AccumulatorIOP::sample_coins(&mut prover_trans, &instance_ef);
        let randomness_ntt = <NTTIOP<EF>>::sample_coins(&mut prover_trans, &instance_info.ntt_info);
        AccumulatorIOP::<EF>::prove_as_subprotocol(
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
        );
        let poly_info = sumcheck_poly.info();
        let ntt_instance_info = ntt_instance.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Accumulator");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();

        // 2.? [one more step] Prover recursive prove the evaluation of F(u, v)
        let recursive_proof = <NTTIOP<EF>>::prove_recursion(
            &mut prover_trans,
            &sumcheck_state.randomness,
            &ntt_instance_info,
            &prover_u,
        );
        iop_proof_size += bincode::serialize(&recursive_proof).unwrap().len();
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
            <AccumulatorIOP<EF>>::num_coins(&instance_info),
        );
        let randomness_ntt = verifier_trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<EF>>::num_coins(&instance_info.ntt_info),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in ACC");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subclaim = AccumulatorIOP::<EF>::verify_as_subprotocol(
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

impl<F: Field + Serialize> AccumulatorIOPPure<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &AccumulatorInstance<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            instance.num_updations * (<RlweMultRgswIOPPure<F>>::num_coins() + 2),
        )
    }

    /// Return the number of random coins used in this IOP
    pub fn num_coins(info: &AccumulatorInstanceInfo<F>) -> usize {
        info.num_updations * (<RlweMultRgswIOPPure<F>>::num_coins() + 2)
    }

    /// Prove accumulator updating `num_updations`` times
    #[inline]
    pub fn prove(instance: &AccumulatorInstance<F>) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut trans = Transcript::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));
        let randomness = Self::sample_coins(&mut trans, instance);
        let randomness_ntt = <NTTIOP<F>>::sample_coins(&mut trans, &instance.ntt_info);

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();
        // add sumcheck products (without NTT) into poly
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck_products of NTT into poly
        let ntt_instance = instance.extract_ntt_instance(&randomness_ntt);
        <NTTBareIOP<F>>::prepare_products_of_polynomial(
            F::one(),
            &mut poly,
            &mut claimed_sum,
            &ntt_instance,
            &u,
        );

        // prove all sumcheck protocol into a large random sumcheck
        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof =
            <NTTIOP<F>>::prove_recursion(&mut trans, &state.randomness, &ntt_instance.info(), &u);

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

    /// Verify the accumulator updating `num_updations` times
    #[inline]
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &AccumulatorEval<F>,
        evals_at_u: &AccumulatorEval<F>,
        info: &AccumulatorInstanceInfo<F>,
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
            <NTTIOP<F>>::num_coins(&info.ntt_info),
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
        <NTTIOP<F>>::verify_recursion(&mut trans, recursive_proof, &info.ntt_info, &u, &subclaim)
    }
    /// Prover Accumulator
    #[inline]
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &AccumulatorInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let r_each_num = RlweMultRgswIOPPure::<F>::num_coins() + 2;
        assert_eq!(randomness.len(), instance.num_updations * r_each_num);

        // in other updations, acc_ntt = acc_ntt (in last updation) + output_ntt of RLWE * RGSW
        for (updation, r) in izip!(&instance.updations, randomness.chunks_exact(r_each_num)) {
            let (r, r_mult) = r.split_at(2);
            // When proving ACC = ACC + (x^a_u - 1) * ACC * RGSW
            // step 1. `ACC` * `d` = RLWE
            // sum_x eq(u, x) * (ACC.a(x) * d(x) - a(x)) = 0
            poly.add_product(
                [
                    Rc::new(updation.d_ntt.clone()),
                    Rc::new(updation.acc_ntt.a.clone()),
                    eq_at_u.clone(),
                ],
                r[0],
            );
            poly.add_product(
                [
                    Rc::new(updation.input_rlwe_ntt.a.clone()),
                    Rc::clone(eq_at_u),
                ],
                -r[0],
            );
            // sum_x eq(u, x) * (ACC.b(x) * d(x) - RLWE.b(x)) = 0
            poly.add_product(
                [
                    Rc::new(updation.d_ntt.clone()),
                    Rc::new(updation.acc_ntt.b.clone()),
                    eq_at_u.clone(),
                ],
                r[1],
            );
            poly.add_product(
                [
                    Rc::new(updation.input_rlwe_ntt.b.clone()),
                    Rc::clone(eq_at_u),
                ],
                -r[1],
            );

            // step2: RLWE * RGSW
            <RlweMultRgswIOPPure<F>>::prove_as_subprotocol(
                r_mult,
                poly,
                &updation.rlwe_mult_rgsw,
                eq_at_u,
            );
        }
    }

    /// Verify the sumcheck part of accumulator updations (not including NTT part)
    #[inline]
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &AccumulatorEval<F>,
        info: &AccumulatorInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        let r_each_num = RlweMultRgswIOPPure::<F>::num_coins() + 2;
        assert_eq!(randomness.len(), info.num_updations * r_each_num);

        // check the sumcheck part
        for (updation, r) in izip!(&evals.updations, randomness.chunks_exact(r_each_num)) {
            let (r, r_mult) = r.split_at(2);
            subclaim.expected_evaluations -= eq_at_u_r
                * (r[0] * (updation.d_ntt * updation.acc_ntt.0 - updation.input_rlwe_ntt.0)
                    + r[1] * (updation.d_ntt * updation.acc_ntt.1 - updation.input_rlwe_ntt.1));
            if !RlweMultRgswIOPPure::verify_as_subprotocol(
                r_mult,
                subclaim,
                &updation.rlwe_mult_rgsw,
                &info.mult_info,
                eq_at_u_r,
            ) {
                return false;
            }
        }

        // check the equality relations among the accmulator updations
        for (this, next) in evals.updations.iter().tuple_windows() {
            let this_acc = &this.acc_ntt;
            let this_mult = &this.rlwe_mult_rgsw.output_rlwe_ntt;
            let next_acc = &next.acc_ntt;
            if !(this_acc.0 + this_mult.0 == next_acc.0 && this_acc.1 + this_mult.1 == next_acc.1) {
                return false;
            }
        }
        true
    }
}

impl<F, EF> AccumulatorSnarksOpt<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &AccumulatorInstance<F>, code_spec: &S, block_size: usize)
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

        let start = Instant::now();
        lookup_instance.generate_h_vec(random_value);
        println!("batch inverse: {:?} ms", start.elapsed().as_millis());
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
        let randomness = AccumulatorIOPPure::sample_coins(&mut prover_trans, &instance_ef);
        let randomness_ntt = <NTTIOP<EF>>::sample_coins(&mut prover_trans, &instance_info.ntt_info);
        AccumulatorIOPPure::<EF>::prove_as_subprotocol(
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
        );

        iop_proof_size += bincode::serialize(&recursive_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();

        // let evals_at_r = instance.evaluate_ext(&sumcheck_state.randomness);
        // let evals_at_u = instance.evaluate_ext(&prover_u);

        let (evals_at_r, evals_at_u) = rayon::join(
            || instance.evaluate_ext(&sumcheck_state.randomness),
            || instance.evaluate_ext(&prover_u),
        );
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

        let mut opens = BrakedownPCS::<F, H, C, S, EF>::batch_open(
            &pp,
            &comm,
            &comm_state,
            &[requested_point_at_r.clone(), requested_point_at_u.clone()],
            &mut prover_trans,
        );

        let eval_proof_at_r = std::mem::take(&mut opens[0]);
        let eval_proof_at_u = std::mem::take(&mut opens[1]);

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
            <AccumulatorIOPPure<EF>>::num_coins(&instance_info),
        );
        let randomness_ntt = verifier_trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            <NTTIOP<EF>>::num_coins(&instance_info.ntt_info),
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
        .expect("Verify the sumcheck proof generated in Accumulator");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subclaim = AccumulatorIOPPure::<EF>::verify_as_subprotocol(
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

        let check_pcs_at_r_and_u = BrakedownPCS::<F, H, C, S, EF>::batch_verify(
            &pp,
            &comm,
            &[requested_point_at_r, requested_point_at_u],
            &[oracle_eval_at_r, oracle_eval_at_u],
            &[eval_proof_at_r.clone(), eval_proof_at_u.clone()],
            &mut verifier_trans,
        );

        assert!(check_pcs_at_r_and_u);

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

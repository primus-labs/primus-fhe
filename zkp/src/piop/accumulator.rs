//! IOP for Accumulator updating t times
//! ACC = ACC + (X^{-a_u} - 1) * ACC * RGSW(Z_u)
//! Each updation contains two single ntt operations and one multiplication between RLWE and RGSW
use crate::{
    piop::LookupIOP,
    sumcheck::{self, verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit},
};

use core::fmt;
use std::{marker::PhantomData, rc::Rc, sync::Arc};

use super::{
    external_product::{
        ExternalProductInstanceEval, ExternalProductInstanceInfo, ExternalProductInstanceInfoClean,
        RlweEval,
    },
    ntt::{BatchNTTInstanceInfoClean, BitsOrder, NTTRecursiveProof},
    BatchNTTInstanceInfo, BitDecompositionInstance, BitDecompositionInstanceInfo,
    ExternalProductIOP, ExternalProductInstance, LookupInstance, LookupInstanceEval,
    LookupInstanceInfo, NTTBareIOP, NTTInstance, RlweCiphertext, NTTIOP,
};
use crate::utils::{
    add_assign_ef, eval_identity_function, gen_identity_evaluations, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use bincode::Result;
use itertools::{izip, Itertools};
use pcs::PolynomialCommitmentScheme;
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator,
        ParallelIterator,
    },
    slice::ParallelSlice,
};
use serde::{Deserialize, Serialize};

/// The Accumulator witness when performing ACC = ACC + (X^{-a_u} - 1) * ACC * RGSW(Z_u)
#[derive(Debug, Clone)]
pub struct AccumulatorWitness<F: Field> {
    /// The NTT form of ACC.
    pub acc_ntt: RlweCiphertext<F>,
    /// The coefficient form of scalar d = (X^{-a_u} - 1).
    pub d: DenseMultilinearExtension<F>,
    /// The NTT form of scalar d = (X^{-a_u} - 1).
    pub d_ntt: DenseMultilinearExtension<F>,
    /// The NTT form of d * ACC.
    pub input_rlwe_ntt: RlweCiphertext<F>,
    /// The output of input_rlwe * RGSW(Z_u)
    pub rlwe_mult_rgsw: ExternalProductInstance<F>,
}

/// Evaluation of AccumulatorWitnessEval at the same random point
#[derive(Serialize, Deserialize)]
pub struct AccumulatorWitnessEval<F: Field> {
    /// The evaluation of the NTT form of ACC.
    pub acc_ntt: RlweEval<F>,
    /// The evaluation of the coefficient form of scalar d.
    pub d: F,
    /// The evaluation of the NTT form of scalar d.
    pub d_ntt: F,
    /// The evaluation of the NTT form of d * ACC.
    pub input_rlwe_ntt: RlweEval<F>,
    /// The evaluation of the ExternalProduct.
    pub rlwe_mult_rgsw: ExternalProductInstanceEval<F>,
}

/// Store the ntt instance, bit decomposition instance, and the sumcheck instance for an Accumulator updating `t` times
pub struct AccumulatorInstance<F: Field> {
    /// The number of variables.
    pub num_vars: usize,
    /// The number of updations.
    pub num_updations: usize,
    /// The input of the Accumulator, represented in coefficient form
    pub input: RlweCiphertext<F>,
    /// The witnesses stored in updations
    pub updations: Vec<AccumulatorWitness<F>>,
    /// The output of the Accumulator, represented in NTT form
    pub output_ntt: RlweCiphertext<F>,
    /// The output of the Accumulator, represented in coefficient form
    pub output: RlweCiphertext<F>,
    /// The info for RLWE * RGSW
    pub mult_info: ExternalProductInstanceInfo<F>,
    /// The info for decomposed bits
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// The info for NTT
    pub ntt_info: BatchNTTInstanceInfo<F>,
}

/// Evaluation of AccumulatorInstance at the same random point
#[derive(Default, Serialize, Deserialize)]
pub struct AccumulatorInstanceEval<F: Field> {
    /// The evaluation of the input of the Accumulator in coefficient form.
    pub input: RlweEval<F>,
    /// The evaluations of the witnesses stored in updations.
    pub updations: Vec<AccumulatorWitnessEval<F>>,
    /// The evaluation of the output of the Accumulator in NTT form.
    pub output_ntt: RlweEval<F>,
    /// The evaluation of the output of the Accumulator in coefficient form.
    pub output: RlweEval<F>,
}

/// Store the Accumulator info used to verify
pub struct AccumulatorInstanceInfo<F: Field> {
    /// The number of variables.
    pub num_vars: usize,
    /// The number of updations.
    pub num_updations: usize,
    /// The info for RLWE * RGSW.
    pub mult_info: ExternalProductInstanceInfo<F>,
    /// The info for decomposed bits.
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// The info for NTT.
    pub ntt_info: BatchNTTInstanceInfo<F>,
}

/// Stores the information to be hashed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatorInstanceInfoClean<F: Field> {
    /// The number of variables.
    pub num_vars: usize,
    /// The number of updations.
    pub num_updations: usize,
    /// The info for RLWE * RGSW.
    pub mult_info: ExternalProductInstanceInfoClean<F>,
    /// The info for decomposed bits.
    pub bits_info: BitDecompositionInstanceInfo<F>,
    /// The info for NTT.
    pub ntt_info: BatchNTTInstanceInfoClean,
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

impl<F: Field> AccumulatorInstanceInfo<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.num_updations * (6 + self.mult_info.num_oracles())
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
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> AccumulatorInstanceInfo<EF> {
        AccumulatorInstanceInfo {
            num_vars: self.num_vars,
            num_updations: self.num_updations,
            mult_info: self.mult_info.to_ef(),
            bits_info: self.bits_info.to_ef(),
            ntt_info: self.ntt_info.to_ef(),
        }
    }

    /// Convert to clean info.
    #[inline]
    pub fn to_clean(&self) -> AccumulatorInstanceInfoClean<F> {
        AccumulatorInstanceInfoClean {
            num_vars: self.num_vars,
            num_updations: self.num_updations,
            mult_info: self.mult_info.to_clean(),
            bits_info: self.bits_info.clone(),
            ntt_info: self.ntt_info.to_clean(),
        }
    }

    /// Extract lookup info.
    #[inline]
    pub fn extract_lookup_info(&self, block_size: usize) -> LookupInstanceInfo {
        LookupInstanceInfo {
            num_vars: self.num_vars,
            num_batch: 2 * self.bits_info.bits_len * self.num_updations,
            block_size,
            block_num: (2 * self.bits_info.bits_len * self.num_updations + block_size) / block_size,
        }
    }
}

impl<F: Field> AccumulatorWitness<F> {
    /// Return the output_ntt
    #[inline]
    pub fn get_output(&self) -> RlweCiphertext<F> {
        self.rlwe_mult_rgsw.output_rlwe_ntt.clone()
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

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> AccumulatorWitnessEval<EF> {
        AccumulatorWitnessEval {
            acc_ntt: self.acc_ntt.evaluate_ext_opt(point),
            d: self.d.evaluate_ext_opt(point),
            d_ntt: self.d_ntt.evaluate_ext_opt(point),
            input_rlwe_ntt: self.input_rlwe_ntt.evaluate_ext_opt(point),
            rlwe_mult_rgsw: self.rlwe_mult_rgsw.evaluate_ext_opt(point),
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
        res.extend::<Vec<F>>(
            self.updations
                .par_iter()
                .flat_map(|updation| updation.pack_all_mles())
                .collect(),
        );
        res
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    #[inline]
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let info = self.info();
        let num_vars = info.generate_num_var();
        let num_zeros_padded = (1 << num_vars) - info.num_oracles() * (1 << self.num_vars);

        let mut evals = self.pack_all_mles();
        evals.extend(&vec![F::zero(); num_zeros_padded]);
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
                .par_iter()
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
    pub fn evaluate(&self, point: &[F]) -> AccumulatorInstanceEval<F> {
        AccumulatorInstanceEval::<F> {
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
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> AccumulatorInstanceEval<EF> {
        AccumulatorInstanceEval::<EF> {
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

    /// Evaluate at the same random point defined over EF
    #[inline]
    pub fn evaluate_ext_opt<EF: AbstractExtensionField<F>>(
        &self,
        point: &DenseMultilinearExtension<EF>,
    ) -> AccumulatorInstanceEval<EF> {
        AccumulatorInstanceEval::<EF> {
            input: self.input.evaluate_ext_opt(point),
            output_ntt: self.output_ntt.evaluate_ext_opt(point),
            output: self.output.evaluate_ext_opt(point),
            updations: self
                .updations
                .par_iter()
                .map(|updation| updation.evaluate_ext_opt(point))
                .collect(),
        }
    }

    /// Extract all ntt instances contained into a single random NTT instance
    #[inline]
    pub fn extract_ntt_instance(&self, randomness: &[F]) -> NTTInstance<F> {
        assert_eq!(randomness.len(), self.num_ntt_contained());
        let mut random_coeffs = DenseMultilinearExtension::<F>::from_evaluations_vec(
            self.num_vars,
            vec![F::zero(); 1 << self.num_vars],
        );
        let mut random_points = DenseMultilinearExtension::<F>::from_evaluations_vec(
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

        let zero = DenseMultilinearExtension {
            num_vars: self.num_vars,
            evaluations: vec![F::zero(); 1 << self.num_vars],
        };

        let mut par_random_coeffs: Vec<DenseMultilinearExtension<F>> =
            vec![zero.clone(); self.updations.len()];
        let mut par_random_points: Vec<DenseMultilinearExtension<F>> =
            vec![zero.clone(); self.updations.len()];

        self.updations
            .par_iter()
            .zip(r.par_chunks_exact(r_each_num))
            .zip(par_random_coeffs.par_iter_mut())
            .zip(par_random_points.par_iter_mut())
            .for_each(|(((updation, r_each), coeffs), points)| {
                updation.update_ntt_instance(coeffs, points, r_each);
            });

        let random_coeffs = par_random_coeffs
            .iter()
            .fold(random_coeffs, |acc, x| acc + x);

        let random_points = par_random_points
            .iter()
            .fold(random_points, |acc, x| acc + x);

        NTTInstance::<F> {
            num_vars: self.num_vars,
            ntt_table: self.ntt_info.ntt_table.clone(),
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

impl<F: Field> AccumulatorInstanceEval<F> {
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

/// IOP for Accumulator
#[derive(Default)]
pub struct AccumulatorIOP<F: Field> {
    /// The random vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random vector for ntt.
    pub randomness_ntt: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> AccumulatorIOP<F> {
    /// Sample the random coins before proving sumcheck protocol
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    pub fn sample_coins(trans: &mut Transcript<F>, info: &AccumulatorInstanceInfo<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        )
    }

    /// Return the number of random coins used in this IOP
    pub fn num_coins(info: &AccumulatorInstanceInfo<F>) -> usize {
        info.num_updations * (ExternalProductIOP::<F>::num_coins() + 2)
    }

    /// Generate the randomness.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The accumulator instance info.
    #[inline]
    pub fn generate_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        info: &AccumulatorInstanceInfo<F>,
    ) {
        self.randomness = Self::sample_coins(trans, info);
        self.randomness_ntt = NTTIOP::<F>::sample_coins(trans, &info.ntt_info.to_clean());
        self.u = trans.get_vec_challenge(
            b"ACC IOP: random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// Prove accumulator updating `num_updations`` times.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `instance` - The external product instance.
    /// * `lookup_instance` - The extracted lookup instance.
    /// * `lookup_iop` - The lookup IOP.
    /// * `bits_order` - The indicator of bits order.
    #[inline]
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &AccumulatorInstance<F>,
        lookup_instance: &LookupInstance<F>,
        lookup_iop: &LookupIOP<F>,
        bits_order: BitsOrder,
    ) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let mut claimed_sum = F::zero();

        // add sumcheck products (without NTT) into poly
        Self::prepare_products_of_polynomial(&self.randomness, &mut poly, instance, &eq_at_u);

        // add sumcheck_products of NTT into poly
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

    /// Prover Accumulator
    #[inline]
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &AccumulatorInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let r_each_num = ExternalProductIOP::<F>::num_coins() + 2;
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
            ExternalProductIOP::<F>::prepare_products_of_polynomial(
                r_mult,
                poly,
                &updation.rlwe_mult_rgsw,
                eq_at_u,
            );
        }
    }

    /// Verify the accumulator updating `num_updations` times
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
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: &AccumulatorInstanceEval<F>,
        evals_at_u: &AccumulatorInstanceEval<F>,
        info: &AccumulatorInstanceInfo<F>,
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

    /// Verify the sumcheck part of accumulator updations (not including NTT part)
    #[inline]
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &AccumulatorInstanceEval<F>,
        info: &AccumulatorInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        let r_each_num = ExternalProductIOP::<F>::num_coins() + 2;
        assert_eq!(randomness.len(), info.num_updations * r_each_num);

        // check the sumcheck part
        for (updation, r) in izip!(&evals.updations, randomness.chunks_exact(r_each_num)) {
            let (r, r_mult) = r.split_at(2);
            subclaim.expected_evaluations -= eq_at_u_r
                * (r[0] * (updation.d_ntt * updation.acc_ntt.0 - updation.input_rlwe_ntt.0)
                    + r[1] * (updation.d_ntt * updation.acc_ntt.1 - updation.input_rlwe_ntt.1));
            if !ExternalProductIOP::verify_subclaim(
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

/// Accumulator proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct AccumulatorProof<
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
    /// The accumulator evaluations.
    pub acc_evals_at_r: AccumulatorInstanceEval<EF>,
    /// The accumulator evaluations.
    pub acc_evals_at_u: AccumulatorInstanceEval<EF>,
    /// The lookup evaluations.
    pub lookup_evals: LookupInstanceEval<EF>,
    /// The claimed sum from sumcheck.
    pub claimed_sum: EF,
}

impl<F, EF, S, Pcs> AccumulatorProof<F, EF, S, Pcs>
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

/// Accumulator parameters.
pub struct AccumulatorParams<
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

impl<F, EF, S, Pcs> Default for AccumulatorParams<F, EF, S, Pcs>
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

impl<F, EF, S, Pcs> AccumulatorParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    pub fn setup(&mut self, info: &AccumulatorInstanceInfo<F>, block_size: usize, code_spec: S) {
        self.pp_first = Pcs::setup(info.generate_num_var(), Some(code_spec.clone()));

        let lookup_info = info.extract_lookup_info(block_size);
        self.pp_second = Pcs::setup(lookup_info.generate_second_num_var(), Some(code_spec));
    }
}

/// Prover for Accumulator with PCS.
pub struct AccumulatorProver<
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

impl<F, EF, S, Pcs> Default for AccumulatorProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        AccumulatorProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> AccumulatorProver<F, EF, S, Pcs>
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
        params: &AccumulatorParams<F, EF, S, Pcs>,
        instance: &AccumulatorInstance<F>,
        block_size: usize,
        bits_order: BitsOrder,
    ) -> AccumulatorProof<F, EF, S, Pcs> {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");

        // It is better to hash the shared public instance information, including the table.
        trans.append_message(b"accumulator instance", &instance_info.to_clean());

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let first_committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (first_comm, first_comm_state) = Pcs::commit(&params.pp_first, &first_committed_poly);

        trans.append_message(b"ACC IOP: first commitment", &first_comm);

        println!(
            "first polynomial has {:?} variables",
            first_committed_poly.num_vars
        );

        // Convert the original instance into an instance defined over EF
        let instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // IOPs
        let mut acc_iop = AccumulatorIOP::<EF>::default();
        let mut lookup_iop = LookupIOP::<EF>::default();

        // generate ranomness for ACC iop.
        acc_iop.generate_randomness(trans, &instance_info);

        // --- Lookup instance and commitment ---
        let mut lookup_instance = instance_ef.extract_lookup_instance(block_size);

        let lookup_info = lookup_instance.info();
        println!("- containing {lookup_info}\n");

        // Generate the first randomness for lookup iop.
        lookup_iop.prover_generate_first_randomness(trans, &mut lookup_instance);

        // Compute the packed second polynomials for lookup, i.e., h vector.
        let second_committed_poly = lookup_instance.generate_second_oracle();

        // Commit the second polynomial.
        let (second_comm, second_comm_state) =
            Pcs::commit_ef(&params.pp_second, &second_committed_poly);

        trans.append_message(b"ACC IOP: second commitment", &second_comm);

        println!(
            "second polynomial has {:?} variables",
            second_committed_poly.num_vars
        );

        lookup_iop.generate_second_randomness(trans, &lookup_info);

        let (kit, recursive_proof) = acc_iop.prove(
            trans,
            &instance_ef,
            &lookup_instance,
            &lookup_iop,
            bits_order,
        );

        // Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol

        // let evals_at_r = instance.evaluate_ext(&sumcheck_state.randomness);
        // let evals_at_u = instance.evaluate_ext(&prover_u);

        // TODO: use evaluate_opt.

        // let acc_evals_at_r = instance.evaluate_ext(&kit.randomness);
        // let acc_evals_at_u = instance.evaluate_ext(&acc_iop.u);

        let (acc_evals_at_r, acc_evals_at_u) = rayon::join(
            || instance.evaluate_ext(&kit.randomness),
            || instance.evaluate_ext(&acc_iop.u),
        );

        // --- Lookup Part ---
        let lookup_evals = lookup_instance.evaluate(&kit.randomness);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point_at_r = kit.randomness.clone();
        let mut requested_point_at_u = acc_iop.u.clone();
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
        let mut opens = Pcs::batch_open(
            &params.pp_first,
            &first_comm,
            &first_comm_state,
            &[requested_point_at_r.clone(), requested_point_at_u.clone()],
            trans,
        );

        let first_eval_proof_at_r = std::mem::take(&mut opens[0]);
        let first_eval_proof_at_u = std::mem::take(&mut opens[1]);

        let second_eval_proof = Pcs::open_ef(
            &params.pp_second,
            &second_comm,
            &second_comm_state,
            &second_requested_point,
            trans,
        );

        AccumulatorProof {
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
            acc_evals_at_r,
            acc_evals_at_u,
            lookup_evals,
            claimed_sum: kit.claimed_sum,
        }
    }
}

/// Prover for accumulator with PCS.
pub struct AccumulatorVerifier<
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

impl<F, EF, S, Pcs> Default for AccumulatorVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        AccumulatorVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> AccumulatorVerifier<F, EF, S, Pcs>
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
        params: &AccumulatorParams<F, EF, S, Pcs>,
        info: &AccumulatorInstanceInfo<F>,
        block_size: usize,
        bits_order: BitsOrder,
        proof: &AccumulatorProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"accumulator instance", &info.to_clean());
        trans.append_message(b"ACC IOP: first commitment", &proof.first_comm);

        let mut acc_iop = AccumulatorIOP::<EF>::default();
        let mut lookup_iop = LookupIOP::<EF>::default();
        let info_ef = info.to_ef();

        acc_iop.generate_randomness(trans, &info_ef);
        lookup_iop.verifier_generate_first_randomness(trans);

        trans.append_message(b"ACC IOP: second commitment", &proof.second_comm);

        // Verify the proof of sumcheck protocol.
        let lookup_info = info.extract_lookup_info(block_size);
        lookup_iop.generate_second_randomness(trans, &lookup_info);

        let mut wrapper = ProofWrapper {
            claimed_sum: proof.claimed_sum,
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };

        let (b, randomness) = acc_iop.verify(
            trans,
            &mut wrapper,
            &proof.acc_evals_at_r,
            &proof.acc_evals_at_u,
            &info_ef,
            &lookup_info,
            &proof.recursive_proof,
            &proof.lookup_evals,
            &lookup_iop,
            bits_order,
        );
        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let mut requested_point_at_r = randomness.clone();
        let mut requested_point_at_u = acc_iop.u;
        let flatten_evals_at_r = proof.acc_evals_at_r.flatten();
        let flatten_evals_at_u = proof.acc_evals_at_u.flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            proof.acc_evals_at_r.log_num_oracles(),
        );

        requested_point_at_r.extend(&oracle_randomness);
        requested_point_at_u.extend(&oracle_randomness);

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

        res &= Pcs::batch_verify(
            &params.pp_first,
            &proof.first_comm,
            &[requested_point_at_r, requested_point_at_u],
            &[proof.first_oracle_eval_at_r, proof.first_oracle_eval_at_u],
            &[
                proof.first_eval_proof_at_r.clone(),
                proof.first_eval_proof_at_u.clone(),
            ],
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

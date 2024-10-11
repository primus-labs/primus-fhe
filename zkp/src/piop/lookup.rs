//! PIOP for lookups
//! The prover wants to convince that lookups f are all in range
//!
//! <==> \forall x \in H_f, \forall i \in [lookup_num], f_i(x) \in [range]
//!
//! <==> \forall x in H_f, \forall i \in [lookup_num], f_i(x) \in {t(x) | x \in H_t} := {0, 1, 2, ..., range - 1}  
//!      where |H_f| is the size of one lookup and |H_t| is the size of table / range
//!
//! <==> \exists m s.t. \forall y, \sum_{i} \sum_{x \in H_f} 1 / f_i(x) - y = \sum_{x \in H_t} m(x) / t(x) - y
//!
//! <==> \sum_{i} \sum_{x \in H_f} 1 / f_i(x) - r = \sum_{x \in H_t} m(x) / t(x) - r
//!      where r is a random challenge from verifier (a single random element since y is a single variable)
//!
//! <==> \sum_{x \in H_f} \sum_{i \in [block_num]} h_i(x) = \sum_{x \in H_t} h_t(x)
//!      \forall i \in [block_num] \forall x \in H_f, h(x) * \prod_{j \in [block_size]}(f_j(x) - r) = \sum_{i \in [block_size]} \prod_{j \in [block_size], j != i} (f_j(x) - r)
//!      \forall x \in H_t, h_t(x) * (t(x) - r) = m(x)
//!
//! <==> \sum_{x \in H_f} \sum_{i \in [block_num]} h_i(x) = c_sum
//!      \sum_{x \in H_t} h_t(x) = c_sum
//!      \sum_{x \in H_f} \sum_{i \in [block_num]} eq(x, u) * (h(x) * \prod_{j \in [block_size]}(f_j(x) - r) - r * \sum_{i \in [block_size]} \prod_{j \in [block_size], j != i} (f_j(x) - r)) = 0
//!      \sum_{x \in H_t} eq(x, u) * (h_t(x) * (t(x) - r) - m(x)) = 0
//!      where u is a random challenge given from verifier (a vector of random element) and c_sum is some constant
//!
//! <==> \sum_{x \in H_f} \sum_{i \in [block_num]} h_i(x)
//!                     + \sum_{i \in [block_num]} eq(x, u) * (h(x) * \prod_{j \in [block_size]}(f_j(x) - r) - r * \sum_{i \in [block_size]} \prod_{j \in [block_size], j != i} (f_j(x) - r))
//!                     = c_sum
//!      \sum_{x \in H_t} h_t(x)
//!                     + eq(x, u) * (h_t(x) * (t(x) - r) - m(x))
//!                     = c_sum
//!      where u is a random challenge given from verifier (a vector of random element) and c_sum is some constant

use crate::sumcheck;
use crate::sumcheck::{verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    batch_inverse, eval_identity_function, gen_identity_evaluations, print_statistic,
    verify_oracle_relation,
};
use algebra::PolynomialInfo;
use algebra::{
    utils::Transcript, AbstractExtensionField, AsFrom, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, MultilinearExtension,
};
use bincode::Result;
use core::fmt;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;

/// Stores the parameters used for lookup and the public info for verifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct LookupInstanceInfo {
    /// number of variables for lookups
    pub num_vars: usize,
    /// number of batches
    pub num_batch: usize,
    /// block size
    pub block_size: usize,
    /// number of blocks
    pub block_num: usize,
}

impl fmt::Display for LookupInstanceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "instances of Lookup: num_vars = {}, num_batch = {}, block_size = {}",
            self.num_vars, self.num_batch, self.block_size,
        )
    }
}

/// Stores the parameters used for lookup and the inputs and witness for prover.
#[derive(Serialize)]
pub struct LookupInstance<F: Field> {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars: usize,
    /// block num
    pub block_num: usize,
    /// block_size
    pub block_size: usize,
    /// inputs f
    pub batch_f: Vec<DenseMultilinearExtension<F>>,
    /// inputs table
    pub table: DenseMultilinearExtension<F>,
    /// intermediate oracle h
    pub blocks: Vec<DenseMultilinearExtension<F>>,
    /// intermediate oracle m
    pub freq: DenseMultilinearExtension<F>,
}

impl<F: Field> LookupInstance<F> {
    /// Extract the information of lookup for verification
    #[inline]
    pub fn info(&self) -> LookupInstanceInfo {
        LookupInstanceInfo {
            num_vars: self.num_vars,
            num_batch: self.batch_f.len(),
            block_size: self.block_size,
            block_num: self.block_num,
        }
    }

    /// Construct an empty instance
    #[inline]
    pub fn new(num_vars: usize, table: DenseMultilinearExtension<F>, block_size: usize) -> Self {
        assert_eq!(table.num_vars, num_vars);
        Self {
            num_vars,
            block_num: 0,
            block_size,
            batch_f: Vec::new(),
            table,
            blocks: Vec::new(),
            freq: Default::default(),
        }
    }

    /// Construct a new instance from slice with prepared m.
    #[inline]
    pub fn from_slice_pure(
        num_vars: usize,
        batch_f: &[DenseMultilinearExtension<F>],
        table: DenseMultilinearExtension<F>,
        freq: DenseMultilinearExtension<F>,
        block_size: usize,
    ) -> Self {
        assert!(block_size > 0);
        let column_num = batch_f.len() + 1;
        Self {
            num_vars,
            block_num: (column_num + block_size - 1) / block_size,
            block_size,
            batch_f: batch_f.to_vec(),
            table,
            blocks: Default::default(),
            freq,
        }
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        batch_f: &[DenseMultilinearExtension<F>],
        table: DenseMultilinearExtension<F>,
        block_size: usize,
    ) -> Self {
        assert!(block_size > 0);
        let num_vars = batch_f[0].num_vars;
        let column_num = batch_f.len() + 1;

        let mut m_table = HashMap::new();
        let mut hash_table = HashMap::new();

        table.evaluations.iter().for_each(|&t| {
            m_table
                .entry(t)
                .and_modify(|counter| *counter += 1usize)
                .or_insert(1);
            hash_table.insert(t, 0usize);
        });

        batch_f.iter().for_each(|f| {
            assert_eq!(f.num_vars, num_vars);
            f.evaluations.iter().for_each(|&x| {
                hash_table.entry(x).and_modify(|counter| *counter += 1);
            })
        });

        let m_evaluations: Vec<F> = table
            .evaluations
            .iter()
            .map(|t| {
                let m_f = hash_table[t];
                let m_t = m_table[t];

                let m_f = F::new(F::Value::as_from(m_f as f64));
                let m_t = F::new(F::Value::as_from(m_t as f64));

                m_f / m_t
            })
            .collect();

        let m: DenseMultilinearExtension<F> =
            DenseMultilinearExtension::from_evaluations_slice(num_vars, &m_evaluations);
        Self {
            num_vars,
            block_num: (column_num + block_size - 1) / block_size,
            block_size,
            batch_f: batch_f.to_vec(),
            table,
            blocks: Default::default(),
            freq: m,
        }
    }

    /// Construct an EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> LookupInstance<EF> {
        LookupInstance::<EF> {
            num_vars: self.num_vars,
            block_num: self.block_num,
            block_size: self.block_size,
            batch_f: self.batch_f.iter().map(|x| x.to_ef()).collect(),
            table: self.table.to_ef(),
            blocks: Default::default(),
            freq: self.freq.to_ef(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_first_oracles(&self) -> usize {
        self.batch_f.len() + 2
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_first_oracles(&self) -> usize {
        self.num_first_oracles().next_power_of_two().ilog2() as usize
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_second_oracles(&self) -> usize {
        self.block_num
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_second_oracles(&self) -> usize {
        self.num_second_oracles().next_power_of_two().ilog2() as usize
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_first_mles(&self) -> Vec<F> {
        // arrangement: f | t | m
        self.batch_f
            .iter()
            .flat_map(|x| x.iter())
            .chain(self.table.iter())
            .chain(self.freq.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_second_mles(&self) -> Vec<F> {
        // arrangement: h
        self.blocks
            .iter()
            .flat_map(|x| x.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the number of variables in the first committed polynomial.
    pub fn generate_first_num_var(&self) -> usize {
        self.num_vars + self.log_num_first_oracles()
    }

    /// Generate the number of variables in the second committed polynomial.
    pub fn generate_second_num_var(&self) -> usize {
        self.num_vars + self.log_num_second_oracles()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    pub fn generate_first_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars = self.generate_first_num_var();
        let num_zeros_padded = (1 << num_vars) - self.num_first_oracles() * (1 << self.num_vars);

        let mut evals = self.pack_first_mles();
        evals.extend_from_slice(&vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Generate second oracle
    pub fn generate_second_oracle(&mut self) -> DenseMultilinearExtension<F> {
        let num_vars = self.generate_second_num_var();
        let num_zeros_padded = (1 << num_vars) - self.num_second_oracles() * (1 << self.num_vars);

        let mut evals = self.pack_second_mles();
        evals.extend_from_slice(&vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Generate the h vector.
    pub fn generate_h_vec(&mut self, random_value: F) {
        let num_vars = self.num_vars;

        // integrate t into columns
        let mut ft_vec = self.batch_f.clone();
        ft_vec.push(self.table.clone());

        // construct shifted columns: (f(x) - r)
        let shifted_ft_vec: Vec<F> = ft_vec
            .iter()
            .flat_map(|f| f.iter())
            .map(|&x| x - random_value)
            .collect();

        let num_threads = rayon::current_num_threads();
        // let chunk_size = (shifted_ft_vec.len() + num_threads - 1) / num_threads;
        let chunk_size = shifted_ft_vec.len() / num_threads;

        // construct inversed shifted columns: 1 / (f(x) - r)
        let mut inversed_shifted_ft_evaluation_vec: Vec<F> = shifted_ft_vec
            .par_chunks(chunk_size)
            .map(|x| batch_inverse(x))
            .flatten()
            .collect();

        let total_size = inversed_shifted_ft_evaluation_vec.len();
        inversed_shifted_ft_evaluation_vec[(total_size - (1 << num_vars))..]
            .iter_mut()
            .zip(self.freq.evaluations.iter())
            .for_each(|(inverse_shifted_t, m)| {
                *inverse_shifted_t *= -(*m);
            });

        let chunks = inversed_shifted_ft_evaluation_vec.chunks(self.block_size * (1 << num_vars));

        // construct blocked columns
        let h_vec: Vec<DenseMultilinearExtension<F>> = chunks
            .map(|block| {
                DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    block.chunks_exact(1 << num_vars).fold(
                        vec![F::zero(); 1 << num_vars],
                        |mut h_evaluations, inversed_shifted_f| {
                            inversed_shifted_f
                                .iter()
                                .enumerate()
                                .for_each(|(idx, &val)| {
                                    h_evaluations[idx] += val;
                                });
                            h_evaluations
                        },
                    ),
                )
            })
            .collect();

        self.blocks = h_vec;
    }

    /// Evaluate at a random point defined over base field
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> LookupInstanceEval<F> {
        let mut batch_f = vec![];
        let mut h_vec = vec![];
        let mut table = F::zero();
        let mut freq = F::zero();
        rayon::scope(|s| {
            s.spawn(|_| batch_f = self.batch_f.iter().map(|x| x.evaluate(point)).collect());
            s.spawn(|_| h_vec = self.blocks.iter().map(|x| x.evaluate(point)).collect());
            s.spawn(|_| table = self.table.evaluate(point));
            s.spawn(|_| freq = self.freq.evaluate(point));
        });

        LookupInstanceEval::<F> {
            batch_f,
            table,
            h_vec,
            freq,
        }
    }

    /// Evaluate at a random point defined over extension field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> LookupInstanceEval<EF> {
        // TODO: Parallel
        LookupInstanceEval::<EF> {
            batch_f: self.batch_f.iter().map(|x| x.evaluate_ext(point)).collect(),
            table: self.table.evaluate_ext(point),
            h_vec: self.blocks.iter().map(|x| x.evaluate_ext(point)).collect(),
            freq: self.freq.evaluate_ext(point),
        }
    }
}

/// Evaluations at a random point
#[derive(Serialize, Deserialize)]
pub struct LookupInstanceEval<F: Field> {
    /// f vector
    pub batch_f: Vec<F>,
    /// taget
    pub table: F,
    /// h vector
    pub h_vec: Vec<F>,
    /// m
    pub freq: F,
}

impl<F: Field> LookupInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_first_oracles(&self) -> usize {
        self.batch_f.len() + 2
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_first_oracles(&self) -> usize {
        self.num_first_oracles().next_power_of_two().ilog2() as usize
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_second_oracles(&self) -> usize {
        self.h_vec.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_second_oracles(&self) -> usize {
        self.num_second_oracles().next_power_of_two().ilog2() as usize
    }

    /// Flatten all evals into a vector with the same arrangement of the committed polynomial
    #[inline]
    pub fn first_flatten(&self) -> Vec<F> {
        let mut res: Vec<F> = Vec::new();
        res.extend(self.batch_f.iter().copied());
        res.push(self.table);
        res.push(self.freq);
        res
    }
}

/// SNARKs for lookup tables.
#[derive(Default)]
pub struct LookupIOP<F: Field> {
    /// The random value to generate r.
    pub random_value: F,
    /// The random vector for random linear combination.
    pub randomness: Vec<F>,
    /// The random value for identity function.
    pub u: Vec<F>,
}

// Execute sumcheck for lookup.
impl<F: Field + Serialize> LookupIOP<F> {
    /// Sample coins for random combination.
    #[inline]
    pub fn sample_coins(trans: &mut Transcript<F>, instance_info: &LookupInstanceInfo) -> Vec<F> {
        // TODO: should hash all the instance.
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            instance_info.block_num,
        )
    }

    /// Return the number of coins used in this IOP
    #[inline]
    pub fn num_coins(info: &LookupInstanceInfo) -> usize {
        info.block_num
    }

    /// The prover initiates the h vector and random value.
    pub fn prover_generate_first_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        instance: &mut LookupInstance<F>,
    ) {
        self.random_value = trans.get_challenge(b"random point used to generate the second oracle");

        instance.generate_h_vec(self.random_value);
    }

    /// The verifier generate the first randomness.
    pub fn verifier_generate_first_randomness(&mut self, trans: &mut Transcript<F>) {
        self.random_value = trans.get_challenge(b"random point used to generate the second oracle");
    }

    /// Generate randomness for linear combination and identity function.
    pub fn generate_second_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        instance_info: &LookupInstanceInfo,
    ) {
        self.u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance_info.num_vars,
        );

        self.randomness = Self::sample_coins(trans, instance_info);
        self.randomness.push(self.random_value);
    }

    /// Prove the lookup statement.
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &mut LookupInstance<F>,
    ) -> SumcheckKit<F> {
        let eq_at_u = Rc::new(gen_identity_evaluations(&self.u));

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);

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

    /// Handle the list of products of polynomial.
    pub fn prepare_products_of_polynomial(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &LookupInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let num_vars = instance.num_vars;
        let random_combine = &randomness[0..randomness.len() - 1];
        let random_value = randomness[randomness.len() - 1];

        // integrate t into columns
        let mut ft_vec = instance.batch_f.clone();
        ft_vec.push(instance.table.clone());

        // construct shifted columns: (f(x) - r)
        let shifted_ft_vec: Vec<Rc<DenseMultilinearExtension<F>>> = ft_vec
            .iter()
            .map(|f| {
                let evaluations = f.evaluations.iter().map(|x| *x - random_value).collect();
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    evaluations,
                ))
            })
            .collect();

        // construct the product of polynomials.
        for ((i, h), u_coef) in instance
            .blocks
            .iter()
            .enumerate()
            .zip(random_combine.iter())
        {
            let product = vec![Rc::new(h.clone())];
            let op_coef = vec![(F::one(), F::zero())];
            poly.add_product_with_linear_op(product, &op_coef, F::one());

            let is_last_block = i == instance.blocks.len() - 1;

            let residual_size = (instance.batch_f.len() + 1) % instance.block_size;

            let this_block_size = if is_last_block && (residual_size != 0) {
                residual_size
            } else {
                instance.block_size
            };

            let block =
                &shifted_ft_vec[i * instance.block_size..i * instance.block_size + this_block_size];

            let mut id_op_coef = vec![(F::one(), F::zero()); this_block_size + 2];

            let mut product = block.to_vec();
            product.extend(vec![eq_at_u.clone(), Rc::new(h.clone())]);
            poly.add_product_with_linear_op(product, &id_op_coef, *u_coef);

            id_op_coef.pop();
            id_op_coef.pop();

            for j in 0..this_block_size {
                let mut product = block.to_vec();
                product[j] = eq_at_u.clone();
                if is_last_block && (j == this_block_size - 1) {
                    id_op_coef.push((-F::one(), F::zero()));
                    product.push(Rc::new(instance.freq.clone()));
                }

                poly.add_product_with_linear_op(product, &id_op_coef, -*u_coef);
            }
        }
    }

    /// Verify the lookup statement
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &ProofWrapper<F>,
        evals: &LookupInstanceEval<F>,
        info: &LookupInstanceInfo,
    ) -> (bool, Vec<F>) {
        let mut subclaim = MLSumcheck::verify(trans, &wrapper.info, F::zero(), &wrapper.proof)
            .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&self.u, &subclaim.point);

        if !Self::verify_subclaim(&self.randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return (false, vec![]);
        }

        (subclaim.expected_evaluations == F::zero(), subclaim.point)
    }

    /// Verify the subclaim of the sumcheck.
    pub fn verify_subclaim(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &LookupInstanceEval<F>,
        info: &LookupInstanceInfo,
        eq_at_u_r: F,
    ) -> bool {
        let random_combine = &randomness[0..randomness.len() - 1];
        let random_value = randomness[randomness.len() - 1];

        let mut ft_vec = evals.batch_f.clone();
        ft_vec.push(evals.table);
        let h_vec = &evals.h_vec;
        let m_eval = evals.freq;

        let chunks = ft_vec.chunks_exact(info.block_size);
        let residual = Some(chunks.remainder()).into_iter();

        let mut eval = F::zero();
        for (i, ((h_eval, f_block), r_k)) in h_vec
            .iter()
            .zip(chunks.chain(residual))
            .zip(random_combine.iter())
            .enumerate()
        {
            let is_last_block = i == (h_vec.len() - 1);

            let shifted_f_eval_block: Vec<F> = f_block.iter().map(|f| *f - random_value).collect();

            let sum_of_products: F = (0..shifted_f_eval_block.len())
                .map(|idx: usize| {
                    shifted_f_eval_block
                        .iter()
                        .enumerate()
                        .fold(F::one(), |acc, (i, x)| {
                            let mut mult = F::one();
                            if i != idx {
                                mult *= x;
                            }
                            if is_last_block
                                && (idx == shifted_f_eval_block.len() - 1)
                                && (i == shifted_f_eval_block.len() - 1)
                            {
                                mult *= -m_eval;
                            }
                            acc * mult
                        })
                })
                .fold(F::zero(), |acc, x| acc + x);

            let product = shifted_f_eval_block.iter().fold(F::one(), |acc, x| acc * x);

            eval += *h_eval + eq_at_u_r * r_k * (*h_eval * product - sum_of_products);
        }

        subclaim.expected_evaluations -= eval;

        true
    }
}

/// Lookup proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct LookupProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Instance info
    pub instance_info: LookupInstanceInfo,
    /// polynomial info
    pub poly_info: PolynomialInfo,
    /// The first polynomial commitment.
    pub first_comm: Pcs::Commitment,
    /// The evaluation of the first packed polynomial.
    pub first_oracle_eval: EF,
    /// The opening proof of the first polynomial.
    pub first_eval_proof: Pcs::Proof,
    /// The sumcheck proof.
    pub sumcheck_proof: sumcheck::Proof<EF>,
    /// The evaluations.
    pub evals: LookupInstanceEval<EF>,
}
impl<F, EF, S, Pcs> LookupProof<F, EF, S, Pcs>
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

/// Lookup parameters.
pub struct LookupParams<
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

impl<F, EF, S, Pcs> Default for LookupParams<F, EF, S, Pcs>
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

impl<F, EF, S, Pcs> LookupParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    pub fn setup(&mut self, instance: &LookupInstance<F>, code_spec: S) {
        self.pp_first = Pcs::setup(instance.generate_first_num_var(), Some(code_spec.clone()));

        self.pp_second = Pcs::setup(instance.generate_second_num_var(), Some(code_spec));
    }
}

/// Prover for lookup with PCS.
pub struct LookupProver<
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

impl<F, EF, S, Pcs> Default for LookupProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        LookupProver {
            _marker_f: PhantomData::<F>::default(),
            _marker_ef: PhantomData::<EF>::default(),
            _marker_s: PhantomData::<S>::default(),
            _marker_pcs: PhantomData::<Pcs>::default(),
        }
    }
}

impl<F, EF, S, Pcs> LookupProver<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<EF>,
        params: &LookupParams<F, EF, S, Pcs>,
        instance: &LookupInstance<F>,
    ) -> LookupProof<F, EF, S, Pcs> {
        let instance_info = instance.info();
        // It is better to hash the shared public instance information, including the table.
        trans.append_message(b"lookup instance", &instance_info);

        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let first_committed_poly = instance.generate_first_oracle();

        // Use PCS to commit the above polynomial.
        let (first_comm, first_comm_state) = Pcs::commit(&params.pp_first, &first_committed_poly);

        trans.append_message(b"first commitment", &first_comm);
        // Prover generates the proof
        // Convert the original instance into an instance defined over EF
        let mut instance_ef = instance.to_ef::<EF>();

        let mut lookup_iop = LookupIOP::<EF>::default();

        lookup_iop.prover_generate_first_randomness(trans, &mut instance_ef);

        // TODO: Should commit polynomial h.

        // Generate proof of sumcheck protocol
        lookup_iop.generate_second_randomness(trans, &instance_info);
        let kit = lookup_iop.prove(trans, &mut instance_ef);

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut first_requested_point = kit.randomness.clone();

        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combinaiton for evaluations of oracles",
            instance.log_num_first_oracles(),
        );

        first_requested_point.extend(&oracle_randomness);

        // Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let evals = instance_ef.evaluate(&kit.randomness);

        let first_oracle_eval = first_committed_poly.evaluate_ext(&first_requested_point);

        // Generate the evaluation proof of the requested point.
        let first_eval_proof = Pcs::open(
            &params.pp_first,
            &first_comm,
            &first_comm_state,
            &first_requested_point,
            trans,
        );

        // TODO: handle the second polynomial.
        LookupProof {
            instance_info,
            poly_info: kit.info,
            first_comm,
            first_oracle_eval,
            first_eval_proof,
            sumcheck_proof: kit.proof,
            evals,
        }
    }
}

/// Verifier for lookup with PCS.
pub struct LookupVerifier<
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

impl<F, EF, S, Pcs> Default for LookupVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        LookupVerifier {
            _marker_f: PhantomData::<F>::default(),
            _marker_ef: PhantomData::<EF>::default(),
            _marker_s: PhantomData::<S>::default(),
            _marker_pcs: PhantomData::<Pcs>::default(),
        }
    }
}

impl<F, EF, S, Pcs> LookupVerifier<F, EF, S, Pcs>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// Verify lookup with PCS.
    pub fn verify(
        &self,
        trans: &mut Transcript<EF>,
        params: &LookupParams<F, EF, S, Pcs>,
        proof: &LookupProof<F, EF, S, Pcs>,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"lookup instance", &proof.instance_info);
        trans.append_message(b"first commitment", &proof.first_comm);

        let mut lookup_iop = LookupIOP::<EF>::default();

        lookup_iop.verifier_generate_first_randomness(trans);

        // TODO: hash the commitment of h.

        // Verify the proof of sumcheck protocol.
        lookup_iop.generate_second_randomness(trans, &proof.instance_info);

        let proof_wrapper = ProofWrapper {
            claimed_sum: EF::zero(),
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };
        let (b, randomness) =
            lookup_iop.verify(trans, &proof_wrapper, &proof.evals, &proof.instance_info);

        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let flatten_evals = proof.evals.first_flatten();
        let oracle_randomness = trans.get_vec_challenge(
            b"random linear combinaiton for evaluations of oracles",
            proof.evals.log_num_first_oracles(),
        );

        res &= verify_oracle_relation(&flatten_evals, proof.first_oracle_eval, &oracle_randomness);

        let mut first_requested_point = randomness;
        first_requested_point.extend(&oracle_randomness);
        // Check the evaluation of a random point over the committed oracle.
        res &= Pcs::verify(
            &params.pp_first,
            &proof.first_comm,
            &first_requested_point,
            proof.first_oracle_eval,
            &proof.first_eval_proof,
            trans,
        );
        res
    }
}
/// SNARKs for lookup compiled with PCS
pub struct LookupSnarks<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

impl<F, EF> LookupSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &LookupInstance<F>, code_spec: &S)
    where
        H: Hash + Sync + Send,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
        S: LinearCodeSpec<F, Code = C> + Clone,
    {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");

        let mut prover_trans = Transcript::<EF>::new();

        // 1. First PCS

        // Construct poly
        let first_committed_poly = instance.generate_first_oracle();
        // setup
        let start = Instant::now();
        let first_pp = BrakedownPCS::<F, H, C, S, EF>::setup(
            first_committed_poly.num_vars,
            Some(code_spec.clone()),
        );
        let first_setup_time = start.elapsed().as_millis();
        // commit
        let start = Instant::now();
        let (first_comm, first_comm_state) =
            BrakedownPCS::<F, H, C, S, EF>::commit(&first_pp, &first_committed_poly);
        let first_commit_time = start.elapsed().as_millis();

        // 2. Second PCS

        // Convert the original instance into an instance defined over EF
        let mut instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // Construct poly
        let random_value =
            prover_trans.get_challenge(b"random point used to generate the second oracle");
        instance_ef.generate_h_vec(random_value);
        // let second_committed_poly = instance_ef.generate_second_oracle();
        // Setup
        // let start = Instant::now();
        // let _second_pp = BrakedownPCS::<F, H, C, S, EF>::setup(
        //     second_committed_poly.num_vars,
        //     Some(code_spec.clone()),
        // );
        // let second_setup_time = start.elapsed().as_millis();
        // Commit
        // let start = Instant::now();
        // let (second_comm, second_comm_state) =
        //     BrakedownPCS::<F, H, C, S, EF>::commit(&pp, &second_committed_poly);
        // let second_commit_time = start.elapsed().as_millis();

        // 3. Prover generates the proof
        let prover_start = Instant::now();
        let mut iop_proof_size = 0;

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

        // 3.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let claimed_sum = EF::zero();

        let mut randomness = LookupIOP::sample_coins(&mut prover_trans, &instance_info);
        randomness.push(random_value);

        LookupIOP::prepare_products_of_polynomial(
            &randomness,
            &mut sumcheck_poly,
            &instance_ef,
            &eq_at_u,
        );
        let poly_info = sumcheck_poly.info();

        // 3.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Lookup");

        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 3.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        let evals = instance_ef.evaluate(&sumcheck_state.randomness);

        // 3.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut first_requested_point = sumcheck_state.randomness.clone();
        first_requested_point.extend(&prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_first_oracles(),
        ));
        let first_oracle_eval = first_committed_poly.evaluate_ext(&first_requested_point);

        // 3.6 Generate the evaluation proof of the requested point
        let first_eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
            &first_pp,
            &first_comm,
            &first_comm_state,
            &first_requested_point,
            &mut prover_trans,
        );
        let first_pcs_open_time = start.elapsed().as_millis();

        // 3.7 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        // let mut second_requested_point = sumcheck_state.randomness.clone();
        // second_requested_point.extend(&prover_trans.get_vec_challenge(
        //     b"random linear combination for evaluations of oracles",
        //     instance.log_num_second_oracles(),
        // ));
        // let second_oracle_eval = second_committed_poly.evaluate(&second_requested_point);

        // 3.8 Generate the evaluation proof of the requested point
        // let second_eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
        //     &pp,
        //     &second_comm,
        //     &second_comm_state,
        //     &second_requested_point,
        //     &mut prover_trans,
        // );
        // let second_pcs_open_time = start.elapsed().as_millis();

        // 4. Verifier checks the proof
        let verifier_start = Instant::now();
        let mut verifier_trans = Transcript::<EF>::new();

        let random_value =
            verifier_trans.get_challenge(b"random point used to generate the second oracle");

        // 4.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 4.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let mut randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <LookupIOP<EF>>::num_coins(&instance_info),
        );
        randomness.push(random_value);

        // 4.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in Lookup");

        // 4.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);
        let check_subcliam = LookupIOP::<EF>::verify_subclaim(
            &randomness,
            &mut subclaim,
            &evals,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subcliam && subclaim.expected_evaluations == EF::zero());
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 4.5 Check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut first_pcs_proof_size = 0;
        let flatten_evals = evals.first_flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals.log_num_first_oracles(),
        );
        let check_oracle =
            verify_oracle_relation(&flatten_evals, first_oracle_eval, &oracle_randomness);
        assert!(check_oracle);

        // 3.5 Check the evaluation of a random point over the committed oracle

        let check_pcs = BrakedownPCS::<F, H, C, S, EF>::verify(
            &first_pp,
            &first_comm,
            &first_requested_point,
            first_oracle_eval,
            &first_eval_proof,
            &mut verifier_trans,
        );
        assert!(check_pcs);
        let pcs_verifier_time = start.elapsed().as_millis();
        first_pcs_proof_size += bincode::serialize(&first_eval_proof).unwrap().len()
            + bincode::serialize(&flatten_evals).unwrap().len();

        // 4. print statistic
        print_statistic(
            iop_prover_time + first_pcs_open_time,
            iop_verifier_time + pcs_verifier_time,
            iop_proof_size + first_pcs_proof_size,
            iop_prover_time,
            iop_verifier_time,
            iop_proof_size,
            first_committed_poly.num_vars,
            instance.num_first_oracles(),
            instance.num_vars,
            first_setup_time,
            first_commit_time,
            first_pcs_open_time,
            pcs_verifier_time,
            first_pcs_proof_size,
        )
    }
}

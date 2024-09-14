//! PIOP for range check
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

use crate::sumcheck::{verifier::SubClaim, MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    batch_inverse, eval_identity_function, gen_identity_evaluations, print_statistic,
    verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, AsFrom, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, MultilinearExtension,
};
use core::fmt;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;

/// SNARKs for range check in [T] := [0, T-1]
pub struct Lookup<F: Field>(PhantomData<F>);

/// Stores the parameters used for range check in [T] and the public info for verifier.
#[derive(Clone, Serialize)]
pub struct LookupInstanceInfo {
    /// number of variables for lookups
    pub num_vars: usize,
    /// block num
    pub block_num: usize,
    /// block size
    pub block_size: usize,
    /// residual size
    pub residual_size: usize,
}

impl fmt::Display for LookupInstanceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "instances of Lookup: num_vars = {}, block_num = {}, block_size = {}, residual_size = {}",
            self.num_vars, self.block_num, self.block_size, self.residual_size
        )
    }
}

/// Stores the parameters used for range check in [T] and the inputs and witness for prover.
pub struct LookupInstance<F: Field> {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars: usize,
    /// block num
    pub block_num: usize,
    /// block_size
    pub block_size: usize,
    /// residual size
    pub residual_size: usize,
    /// inputs f
    pub f_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// inputs t
    pub t: Rc<DenseMultilinearExtension<F>>,
    /// intermediate oracle h
    pub h_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// intermediate oracle m
    pub m: Rc<DenseMultilinearExtension<F>>,
}

impl<F: Field> LookupInstance<F> {
    /// Extract the information of range check for verification
    #[inline]
    pub fn info(&self) -> LookupInstanceInfo {
        let column_num = self.f_vec.len() + 1;
        LookupInstanceInfo {
            num_vars: self.num_vars,
            block_size: self.block_size,
            block_num: column_num / self.block_size,
            residual_size: column_num % self.block_size,
        }
    }

    /// Construct an empty instance
    #[inline]
    pub fn new(
        num_vars: usize,
        table: &Rc<DenseMultilinearExtension<F>>,
        block_size: usize,
    ) -> Self {
        assert_eq!(table.num_vars, num_vars);
        Self {
            num_vars,
            block_num: 0,
            block_size,
            residual_size: 0,
            f_vec: Vec::new(),
            t: table.clone(),
            h_vec: Vec::new(),
            m: Default::default(),
        }
    }

    /// append
    #[inline]
    pub fn append_f(&mut self, bits: &[Rc<DenseMultilinearExtension<F>>]) {
        self.f_vec.extend(bits.to_owned());
    }

    /// finish
    #[inline]
    pub fn finish_instance(&mut self) {
        let num_vars = self.num_vars;
        let column_num = self.f_vec.len() + 1;

        let m_evaluations: Vec<F> = self
            .t
            .iter()
            .map(|t_item| {
                let m_f_vec = self.f_vec.iter().fold(F::zero(), |acc, f| {
                    let m_f: usize = f
                        .evaluations
                        .iter()
                        .filter(|&f_item| f_item == t_item)
                        .count();
                    let m_f: F = F::new(F::Value::as_from(m_f as f64));
                    acc + m_f
                });

                let m_t = self
                    .t
                    .evaluations
                    .iter()
                    .filter(|&t_item2| t_item2 == t_item)
                    .count();
                let m_t: F = F::new(F::Value::as_from(m_t as f64));

                m_f_vec / m_t
            })
            .collect();

        let m = Rc::new(DenseMultilinearExtension::from_evaluations_slice(
            num_vars,
            &m_evaluations,
        ));

        // compute the remaining values
        self.m = m;
        self.block_num = column_num / self.block_size;
        self.residual_size = column_num % self.block_size;
    }

    /// new with randomness
    #[inline]
    pub fn new_with_r(
        f_vec: &[Rc<DenseMultilinearExtension<F>>],
        t: Rc<DenseMultilinearExtension<F>>,
        block_size: usize,
        randomness: F,
    ) -> Self {
        let mut instance = Self::from_slice(f_vec, t, block_size);
        instance.generate_h_vec(randomness);
        instance
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        f_vec: &[Rc<DenseMultilinearExtension<F>>],
        t: Rc<DenseMultilinearExtension<F>>,
        block_size: usize,
    ) -> Self {
        let num_vars = f_vec[0].num_vars;
        let column_num = f_vec.len() + 1;

        f_vec.iter().for_each(|x| assert_eq!(x.num_vars, num_vars));
        assert_eq!(t.num_vars, num_vars);

        let m_evaluations: Vec<F> = t
            .evaluations
            .iter()
            .map(|t_item| {
                let m_f_vec = f_vec.iter().fold(F::zero(), |acc, f| {
                    let m_f: usize = f
                        .evaluations
                        .iter()
                        .filter(|&f_item| f_item == t_item)
                        .count();
                    let m_f: F = F::new(F::Value::as_from(m_f as f64));
                    acc + m_f
                });

                let m_t = t
                    .evaluations
                    .iter()
                    .filter(|&t_item2| t_item2 == t_item)
                    .count();
                let m_t: F = F::new(F::Value::as_from(m_t as f64));

                m_f_vec / m_t
            })
            .collect();

        let m = Rc::new(DenseMultilinearExtension::from_evaluations_slice(
            num_vars,
            &m_evaluations,
        ));
        Self {
            num_vars,
            block_num: column_num / block_size,
            block_size,
            residual_size: column_num % block_size,
            f_vec: f_vec.to_vec(),
            t,
            h_vec: Default::default(),
            m,
        }
    }

    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> LookupInstance<EF> {
        LookupInstance::<EF> {
            num_vars: self.num_vars,
            block_num: self.block_num,
            block_size: self.block_size,
            residual_size: self.residual_size,
            f_vec: self.f_vec.iter().map(|x| Rc::new(x.to_ef())).collect(),
            t: Rc::new(self.t.to_ef()),
            h_vec: Default::default(),
            m: Rc::new(self.m.to_ef()),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_first_oracles(&self) -> usize {
        self.f_vec.len() + 2
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_first_oracles(&self) -> usize {
        self.num_first_oracles().next_power_of_two().ilog2() as usize
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_second_oracles(&self) -> usize {
        self.block_num + if self.residual_size != 0 { 1 } else { 0 }
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_second_oracles(&self) -> usize {
        self.num_second_oracles().next_power_of_two().ilog2() as usize
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_first_mles(&self) -> Vec<F> {
        // arrangement: f | t | m
        self.f_vec
            .iter()
            .flat_map(|x| x.iter())
            .chain(self.t.iter())
            .chain(self.m.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding zeros.
    pub fn pack_second_mles(&self) -> Vec<F> {
        // arrangement: h
        self.h_vec
            .iter()
            .flat_map(|x| x.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    pub fn generate_first_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars_added = self.log_num_first_oracles();
        let num_vars = self.num_vars + num_vars_added;
        let num_zeros_padded =
            ((1 << num_vars_added) - self.num_first_oracles()) * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_first_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// generate second oracle
    pub fn generate_second_oracle(&mut self) -> DenseMultilinearExtension<F> {
        let num_vars_added = self.log_num_second_oracles();
        let num_vars = self.num_vars + num_vars_added;
        let num_zeros_padded =
            ((1 << num_vars_added) - self.num_second_oracles()) * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_second_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// generate_h_vec
    pub fn generate_h_vec(&mut self, random_value: F) {
        let num_vars = self.num_vars;

        // integrate t into columns
        let mut ft_vec = self.f_vec.clone();
        ft_vec.push(self.t.clone());

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

        // construct inversed shifted columns: 1 / (f(x) - r)
        let mut inversed_shifted_ft_evaluation_vec = batch_inverse(
            &shifted_ft_vec
                .iter()
                .flat_map(|f| f.iter())
                .cloned()
                .collect::<Vec<F>>(),
        );

        let total_size = inversed_shifted_ft_evaluation_vec.len();

        inversed_shifted_ft_evaluation_vec[(total_size - (1 << num_vars))..]
            .iter_mut()
            .zip(self.m.evaluations.iter())
            .for_each(|(inverse_shifted_t, m)| {
                *inverse_shifted_t *= -(*m);
            });

        let chunks =
            inversed_shifted_ft_evaluation_vec.chunks_exact(self.block_size * (1 << num_vars));

        let residual = chunks.remainder();

        // construct blocked columns
        let mut h_vec: Vec<Rc<DenseMultilinearExtension<F>>> = chunks
            .map(|block| {
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
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
                ))
            })
            .collect();

        let h_residual = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            residual.chunks_exact(1 << num_vars).fold(
                vec![F::zero(); 1 << num_vars],
                |mut acc, f| {
                    f.iter().enumerate().for_each(|(i, &val)| {
                        acc[i] += val;
                    });
                    acc
                },
            ),
        ));

        if self.residual_size != 0 {
            h_vec.push(h_residual)
        };

        self.h_vec = h_vec;
    }

    /// Evaluate at a random point defined over Field
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> LookupInstanceEval<F> {
        LookupInstanceEval::<F> {
            f_vec: self.f_vec.iter().map(|x| x.evaluate(point)).collect(),
            t: self.t.evaluate(point),
            h_vec: self.h_vec.iter().map(|x| x.evaluate(point)).collect(),
            m: self.m.evaluate(point),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> LookupInstanceEval<EF> {
        LookupInstanceEval::<EF> {
            f_vec: self.f_vec.iter().map(|x| x.evaluate_ext(point)).collect(),
            t: self.t.evaluate_ext(point),
            h_vec: self.h_vec.iter().map(|x| x.evaluate_ext(point)).collect(),
            m: self.m.evaluate_ext(point),
        }
    }
}

/// Evaluations at a random point
pub struct LookupInstanceEval<F: Field> {
    /// f_vec
    pub f_vec: Vec<F>,
    /// t
    pub t: F,
    /// h_vec
    pub h_vec: Vec<F>,
    /// m
    pub m: F,
}

impl<F: Field> LookupInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_first_oracles(&self) -> usize {
        self.f_vec.len() + 2
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
        res.extend(self.f_vec.iter().copied());
        res.push(self.t);
        res.push(self.m);
        res
    }
}

// execute sumcheck for
// \sum_{x \in H_f}
//                  r * \sum_{i \in [block_num]} h_i(x)
//                + \sum_{i \in [block_num]} eq(x, u) * (h(x) * \prod_{j \in [block_size]}(f_j(x) - r) - \sum_{i \in [block_size]} \prod_{j \in [block_size], j != i} (f_j(x) - r))
//                = c_sum
impl<F: Field + Serialize> Lookup<F> {
    /// random combine
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &LookupInstance<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            instance.block_num + if instance.residual_size != 0 { 1 } else { 0 },
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &LookupInstanceInfo) -> usize {
        info.block_num + if info.residual_size != 0 { 1 } else { 0 }
    }

    /// verifier challenges.
    pub fn prove(instance: &mut LookupInstance<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();

        let random_value = trans.get_challenge(b"random point used to generate the second oracle");

        instance.generate_h_vec(random_value);

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut randomness = Self::sample_coins(&mut trans, instance);
        randomness.push(random_value);

        let eq_at_u = Rc::new(gen_identity_evaluations(&u));

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);

        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) = MLSumcheck::prove_as_subprotocol(&mut trans, &poly)
            .expect("fail to prove the sumcheck protocol");

        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum: F::zero(),
            randomness: state.randomness,
            u,
        }
    }

    /// Prove bit decomposition given the decomposed bits as prover key.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &LookupInstance<F>,
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let num_vars = instance.num_vars;
        let random_combine = &randomness[0..randomness.len() - 1];
        let random_value = randomness[randomness.len() - 1];

        // integrate t into columns
        let mut ft_vec = instance.f_vec.clone();
        ft_vec.push(instance.t.clone());

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

        // construct poly
        for ((i, h), u_coef) in instance.h_vec.iter().enumerate().zip(random_combine.iter()) {
            let product = vec![h.clone()];
            let op_coef = vec![(F::one(), F::zero())];
            poly.add_product_with_linear_op(product, &op_coef, F::one());

            let is_last_block = i == instance.h_vec.len() - 1;

            let this_block_size = if is_last_block && (instance.residual_size != 0) {
                instance.residual_size
            } else {
                instance.block_size
            };

            let block =
                &shifted_ft_vec[i * instance.block_size..i * instance.block_size + this_block_size];

            let mut id_op_coef = vec![(F::one(), F::zero()); this_block_size + 2];

            let mut product = block.to_vec();
            product.extend(vec![eq_at_u.clone(), h.clone()]);
            poly.add_product_with_linear_op(product, &id_op_coef, *u_coef);

            id_op_coef.pop();
            id_op_coef.pop();

            for j in 0..this_block_size {
                let mut product = block.to_vec();
                product[j] = eq_at_u.clone();
                if is_last_block && (j == this_block_size - 1) {
                    id_op_coef.push((-F::one(), F::zero()));
                    product.push(instance.m.clone());
                }

                poly.add_product_with_linear_op(product, &id_op_coef, -*u_coef);
            }
        }
    }

    /// verify
    pub fn verify(
        wrapper: &ProofWrapper<F>,
        evals: &LookupInstanceEval<F>,
        info: &LookupInstanceInfo,
    ) -> bool {
        let mut trans = Transcript::new();

        let random_value = trans.get_challenge(b"random point used to generate the second oracle");

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        // randomness to combine sumcheck protocols
        let mut randomness = trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        );
        randomness.push(random_value);

        let mut subclaim =
            MLSumcheck::verify_as_subprotocol(&mut trans, &wrapper.info, F::zero(), &wrapper.proof)
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
        evals: &LookupInstanceEval<F>,
        info: &LookupInstanceInfo,
        eq_at_u_r: F,
    ) -> bool {
        let random_combine = &randomness[0..randomness.len() - 1];
        let random_value = randomness[randomness.len() - 1];

        let mut ft_vec = evals.f_vec.clone();
        ft_vec.push(evals.t);
        let h_vec = &evals.h_vec;
        let m_eval = evals.m;

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
            //let h_eval = h.evaluate(point);

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

/// SNARKs for lookup compied with PCS
pub struct LookupSnarks<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

impl<F, EF> LookupSnarks<F, EF>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks_<H, C, S>(instance: &LookupInstance<F>, code_spec: &S)
    where
        H: Hash + Sync + Send,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
        S: LinearCodeSpec<F, Code = C> + Clone,
    {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");
        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_first_oracle();
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
        let mut instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let claimed_sum = EF::zero();
        let prover_randomness = Lookup::sample_coins(&mut prover_trans, &instance_ef);
        Lookup::prove_as_subprotocol(
            &prover_randomness,
            &mut sumcheck_poly,
            &mut instance_ef,
            &eq_at_u,
        );

        let poly_info = sumcheck_poly.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove_as_subprotocol(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        let evals = instance.evaluate_ext(&sumcheck_state.randomness);

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point = sumcheck_state.randomness.clone();
        requested_point.extend(&prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_first_oracles(),
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

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let verifier_randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <Lookup<EF>>::num_coins(&instance_info),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify_as_subprotocol(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in Bit Decompositon");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subcliam = Lookup::<EF>::verify_as_subprotocol(
            &verifier_randomness,
            &mut subclaim,
            &evals,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subcliam && subclaim.expected_evaluations == EF::zero());
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals = evals.first_flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals.log_num_first_oracles(),
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
            instance.num_first_oracles(),
            instance.num_vars,
            setup_time,
            commit_time,
            pcs_open_time,
            pcs_verifier_time,
            pcs_proof_size,
        );
    }

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

        let mut randomness = Lookup::sample_coins(&mut prover_trans, &instance_ef);
        randomness.push(random_value);

        Lookup::prove_as_subprotocol(&randomness, &mut sumcheck_poly, &instance_ef, &eq_at_u);
        let poly_info = sumcheck_poly.info();

        // 3.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove_as_subprotocol(&mut prover_trans, &sumcheck_poly)
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
            <Lookup<EF>>::num_coins(&instance_info),
        );
        randomness.push(random_value);

        // 4.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify_as_subprotocol(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in Lookup");

        // 4.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);
        let check_subcliam = Lookup::<EF>::verify_as_subprotocol(
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

//     /// Verify addition in Zq given the proof and the verification key for bit decomposistion
//     /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
//     /// verifier challenges.
//     pub fn verify0(
//         fs_rng: &mut impl RngCore,
//         proof: &LookupProof<F>,
//         info: &LookupInstanceInfo,
//     ) -> LookupSubclaim<F> {
//         let sampler = <FieldUniformSampler<F>>::new();
//         let random_value = sampler.sample(fs_rng);
//         let random_point: Vec<_> = (0..info.num_vars).map(|_| sampler.sample(fs_rng)).collect();
//         let random_combine: Vec<_> =
//             (0..info.block_num + if info.residual_size == 0 { 0 } else { 1 } + 1)
//                 .map(|_| sampler.sample(fs_rng))
//                 .collect();

//         // execute sumcheck for
//         // \sum_{x \in H_f}
//         // \sum_{i \in [block_num]}  r * h_i(x)
//         //                         + \ eq(x, u) * (h(x) * \prod_{j \in [block_size]}(f_j(x) - r)
//         //                         - \sum_{i \in [block_size]} \prod_{j \in [block_size], j != i} (f_j(x) - r))
//         //                         = c_sum
//         let poly_info = PolynomialInfo {
//             max_multiplicands: info.block_size + 2,
//             num_variables: info.num_vars,
//         };
//         let first_subclaim = MLSumcheck::verify_as_subprotocol(
//             fs_rng,
//             &poly_info,
//             F::zero(), //proof.c_sum,
//             &proof.sumcheck_msg[0],
//         )
//         .expect("sumcheck protocol in range check failed");

//         LookupSubclaim {
//             random_value,
//             random_point,
//             random_combine,
//             sumcheck_points: vec![first_subclaim.point], //, second_subclaim.point],
//             sumcheck_expected_evaluations: vec![
//                 first_subclaim.expected_evaluations,
//                 //second_subclaim.expected_evaluations,
//             ],
//         }
//     }
// }

// impl<F: Field> LookupSubclaim<F> {
//     /// verify the sumcliam
//     #[inline]
//     #[allow(clippy::too_many_arguments)]
//     pub fn verify_subclaim(
//         &self,
//         f_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
//         t: Rc<DenseMultilinearExtension<F>>,
//         oracle: LookupOracle<F>,
//         info: &LookupInstanceInfo,
//     ) -> bool {
//         let u_f = &self.random_point;

//         let block_size = info.block_size;

//         let h_vec = oracle.h_vec;
//         //let h_t = oracle.h_t;
//         let m = oracle.m;
//         let mut ft_vec = f_vec.clone();
//         ft_vec.push(t);

//         let mut eval = F::zero();
//         let point = &self.sumcheck_points[0];

//         let m_eval = m.evaluate(point);

//         let chunks = ft_vec.chunks_exact(block_size);
//         let residual = Some(chunks.remainder()).into_iter();
//         //if residual_size != 0 {chunks = chunks.chain(residual);}

//         for (i, ((h, f_block), r_k)) in h_vec
//             .iter()
//             .zip(chunks.chain(residual))
//             .zip(self.random_combine.iter())
//             .enumerate()
//         {
//             let is_last_block = i == (h_vec.len() - 1);
//             let h_eval = h.evaluate(point);
//             let eq_eval = eval_identity_function(u_f, point);

//             let shifted_f_eval_block: Vec<F> = f_block
//                 .iter()
//                 .map(|f| f.evaluate(point) - self.random_value)
//                 .collect();
//             let sum_of_products: F = (0..shifted_f_eval_block.len())
//                 .map(|idx: usize| {
//                     shifted_f_eval_block
//                         .iter()
//                         .enumerate()
//                         .fold(F::one(), |acc, (i, x)| {
//                             let mut mult = F::one();
//                             if i != idx {
//                                 mult *= x;
//                             }
//                             if is_last_block
//                                 && (idx == shifted_f_eval_block.len() - 1)
//                                 && (i == shifted_f_eval_block.len() - 1)
//                             {
//                                 mult *= -m_eval;
//                             }
//                             acc * mult
//                         })
//                 })
//                 .fold(F::zero(), |acc, x| acc + x);

//             let product = shifted_f_eval_block.iter().fold(F::one(), |acc, x| acc * x);

//             eval += h_eval + eq_eval * r_k * (h_eval * product - sum_of_products);
//         }

//         if eval != self.sumcheck_expected_evaluations[0] {
//             return false;
//         }

//         true
//     }
// }

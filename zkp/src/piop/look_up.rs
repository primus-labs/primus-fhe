//! PIOP for range check
//! The prover wants to convince that lookups f are all in range
//!
//! <==> \forall x in H_f f(x) \in [range]
//!
//! <==> \forall x in H_f f(x) \in {t(x) | x \in H_t} := {0, 1, 2, ..., range - 1}  
//!      where |H_f| is the size of lookups and |H_t| is the size of table / range
//!
//! <==> \exists m s.t. \forall y, \sum_{x \in H_f} 1 / y - f(x) = \sum_{x \in H_t} m(x) / y - t(x)
//!
//! <==> \sum_{x \in H_f} 1 / r - f(x) = \sum_{x \in H_t} m(x) / r - t(x)
//!      where r is a random challenge from verifier (a single random element since y is a single variable)
//!
//! <==> \sum_{x \in H_f} f_inverse(x) = \sum_{x \in H_t} t_inverse(x)
//!      \forall x \in H_f, f_inverse(x) * (r - f(x)) = 1
//!      \forall x \in H_t, t_inverse(x) * (r - t(x)) = m(x)
//!
//! <==> \sum_{x \in H_f} f_inverse(x) = c_sum
//!      \sum_{x \in H_t} t_inverse(x) = c_sum
//!      \sum_{x \in H_f} eq(x, u) * f_inverse(x) * (r - f(x)) = 1
//!      \sum_{x \in H_t} eq(x, u) * (t_inverse(x) * (r - t(x)) -m(x)) = 0
//!      where u is a random challenge given from verifier (a vector of random element) and c_sum is some constant

use std::marker::PhantomData;
use std::rc::Rc;

use crate::sumcheck::prover::ProverMsg;
use crate::utils::eval_identity_function;

use crate::sumcheck::MLSumcheck;
use crate::utils::gen_identity_evaluations;
use algebra::{
    DecomposableField, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials,
    MultilinearExtension, PolynomialInfo,
};
use rand::{seq::IteratorRandom, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// SNARKs for range check in [T] := [0, T-1]
pub struct Lookup<F: Field>(PhantomData<F>);

/// proof generated by prover
pub struct LookupProof<F: Field> {
    /// sumcheck proof for
    /// \sum_{x\in H_F} f_inverse(x) = c_sum
    /// \sum_{x\in H_T} t_inverse(x) = c_sum
    /// \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
    /// \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
    /// where H_F := {0, 1}^log(|F|), H_T := {0, 1}^log(|T|)
    pub sumcheck_msg: Vec<Vec<ProverMsg<F>>>,
    /// c_sum
    pub c_sum: F,
}

/// oracles
pub struct LookupOracle<F: Field> {
    /// f_inverse
    pub h_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// hpi
    pub phi_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// t_inverse
    pub t_inverse: Rc<DenseMultilinearExtension<F>>,
    /// m
    pub m: Rc<DenseMultilinearExtension<F>>,
}

/// subclaim returned to verifier
pub struct LookupSubclaim<F: Field> {
    /// subcliams
    pub sumcheck_points: Vec<Vec<F>>,
    /// expected value returned in the last round of the sumcheck
    pub sumcheck_expected_evaluations: Vec<F>,
}

/// Stores the parameters used for range check in [T] and the inputs and witness for prover.
pub struct LookupInstance<F: Field> {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars_f: usize,
    /// number of variables for range,
    pub num_vars_t: usize,
    /// chunk_size
    pub block_size: usize,
    /// inputs f
    pub f_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// inputs t
    pub t: Rc<DenseMultilinearExtension<F>>,
}

/// Stores the parameters used for range check in [T] and the public info for verifier.
pub struct LookupInstanceInfo {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars_f: usize,
    /// number of variables for range,
    pub num_vars_t: usize,
    /// chunk
    pub block_size: usize,
    /// block num
    pub l: usize,
}

impl<F: Field> LookupInstance<F> {
    /// Extract the information of range check for verification
    #[inline]
    pub fn info(&self) -> LookupInstanceInfo {
        LookupInstanceInfo {
            num_vars_f: self.num_vars_f,
            num_vars_t: self.num_vars_t,
            block_size: self.block_size,
            l: self.f_vec.len() / self.block_size,
        }
    }
}

impl<F: Field> LookupInstance<F> {
    /// Construct a new instance from vector
    #[inline]
    pub fn from_vec(
        f: Vec<Rc<DenseMultilinearExtension<F>>>,
        t: Rc<DenseMultilinearExtension<F>>,
        chunk_size: usize,
    ) -> Self {
        let num_vars_f = f[0].num_vars;
        f.iter().for_each(|x| assert_eq!(x.num_vars, num_vars_f));

        Self {
            num_vars_f: num_vars_f,
            num_vars_t: t.num_vars,
            block_size: chunk_size,
            f_vec: f,
            t,
        }
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        f: &Vec<Rc<DenseMultilinearExtension<F>>>,
        t: &Rc<DenseMultilinearExtension<F>>,
        block_size: usize,
    ) -> Self {
        let num_vars_f = f[0].num_vars;
        f.iter().for_each(|x| assert_eq!(x.num_vars, num_vars_f));

        Self {
            num_vars_f: num_vars_f,
            num_vars_t: t.num_vars,
            block_size,
            f_vec: f.clone(),
            t: Rc::clone(t),
        }
    }
}

impl<F: Field + DecomposableField> Lookup<F> {
    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prove(
        instance: &LookupInstance<F>,
        randomness: &[F],
    ) -> (LookupProof<F>, LookupOracle<F>) {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, instance, randomness)
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        instance: &LookupInstance<F>,
        randomness: &[F],
    ) -> (LookupProof<F>, LookupOracle<F>) {
        let num_vars_f = instance.num_vars_f;
        let num_vars_t = instance.num_vars_t;

        // assume divisible
        let block_size = instance.block_size;
        let l = instance.f_vec.len() / instance.block_size;

        let u = &randomness[..randomness.len() - 1];
        let u_f = &u[0..instance.num_vars_f];
        let u_t = &u[0..instance.num_vars_t];
        let u_l = &u[0..l];
        let r = randomness[randomness.len() - 1];

        let mut m_evaluations = vec![F::zero(); 1 << num_vars_t];
        instance.f_vec.iter().flat_map(|f| f.iter()).for_each(|x| {
            let idx: usize = x.value().into() as usize;
            m_evaluations[idx] += F::one();
        });

        let m = Rc::new(DenseMultilinearExtension::from_evaluations_slice(
            num_vars_t,
            &m_evaluations,
        ));

        let phi_vec: Vec<Rc<DenseMultilinearExtension<F>>> = instance
            .f_vec
            .iter()
            .map(|f| {
                let evaluations = f.evaluations.iter().map(|x| r - *x).collect();
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    num_vars_f,
                    evaluations,
                ))
            })
            .collect();

        let h_vec: Vec<Rc<DenseMultilinearExtension<F>>> = phi_vec
            .chunks_exact(instance.block_size)
            .map(|chunk| {
                let mut h = vec![F::zero(); 1 << num_vars_f];
                chunk.iter().for_each(|phi| {
                    phi.iter()
                        .enumerate()
                        .for_each(|(i, x)| h[i] += F::one() / x)
                });
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    num_vars_f, h,
                ))
            })
            .collect();

        let t_inverse = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars_t,
            instance
                .t
                .iter()
                .zip(m.evaluations.iter())
                .map(|(x_t, x_m)| *x_m / (r - x_t))
                .collect(),
        ));

        // compute c_sum = sum of f_inverse at H_F
        let c_sum = t_inverse
            .evaluations
            .iter()
            .fold(F::zero(), |sum, x| sum + x);

        dbg!(c_sum);

        let mut sum = F::zero();
        h_vec.iter().flat_map(|h| h.iter()).for_each(|x| {
            sum += x;
        });

        dbg!(sum);

        let mut sumcheck_msg = Vec::new();

        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_f);
        h_vec
            .iter()
            .enumerate()
            .zip(u_l.iter())
            .for_each(|((i, h), u_coef)| {
                let product = vec![h.clone()];
                let op_coef = vec![(F::one(), F::zero())];
                poly.add_product_with_linear_op(product, &op_coef, F::one());

                let chunk = &phi_vec[i * block_size..(i + 1) * block_size];
                let id_u = Rc::new(gen_identity_evaluations(u_f));
                let mut id_op_coef = vec![(F::one(), F::zero()); block_size + 2];

                let mut product = chunk.to_vec();
                product.extend(vec![id_u.clone(), h.clone()]);
                poly.add_product_with_linear_op(product, &id_op_coef, *u_coef);

                id_op_coef.pop();
                id_op_coef.pop();

                for j in 0..block_size {
                    let mut product = chunk.to_vec();
                    product[j] = id_u.clone();
                    poly.add_product_with_linear_op(product, &id_op_coef, -*u_coef);
                }
            });

        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        // // 1. execute sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        // let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_f);
        // let product = vec![Rc::clone(&f_inverse)];
        // let op_coef = vec![(F::one(), F::zero())];
        // poly.add_product_with_linear_op(product, &op_coef, F::one());
        // let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
        //     .expect("sumcheck for rangecheck failed");
        // sumcheck_msg.push(sumcheck_proof.0);

        // 2. execute sumcheck for \sum_{x\in H_T} t_inverse(x) = c_sum
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_t);



        let product = vec![Rc::clone(&t_inverse)];
        let op_coef = vec![(F::one(), F::zero())];
        poly.add_product_with_linear_op(product, &op_coef, F::one());

        let mut product = Vec::with_capacity(3);
        let mut op_coef = Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u_t)));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::clone(&t_inverse));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::clone(&instance.t));
        op_coef.push((-F::one(), r));
        poly.add_product_with_linear_op(product, &op_coef, F::one());

        let mut product = Vec::with_capacity(2);
        let mut op_coef = Vec::with_capacity(2);
        product.push(Rc::new(gen_identity_evaluations(u_t)));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::clone(&m));
        op_coef.push((F::one(), F::zero()));
        poly.add_product_with_linear_op(product, &op_coef, -F::one());

        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        // // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        // let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_f);
        // let mut product = Vec::with_capacity(3);
        // let mut op_coef = Vec::with_capacity(3);
        // product.push(Rc::new(gen_identity_evaluations(u_f)));
        // op_coef.push((F::one(), F::zero()));
        // product.push(Rc::clone(&f_inverse));
        // op_coef.push((F::one(), F::zero()));
        // product.push(instance.fs.clone());
        // op_coef.push((-F::one(), r));
        // poly.add_product_with_linear_op(product, &op_coef, F::one());
        // let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
        //     .expect("sumcheck for rangecheck failed");
        // sumcheck_msg.push(sumcheck_proof.0);

        // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        // let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_t);

        // let mut product = Vec::with_capacity(3);
        // let mut op_coef = Vec::with_capacity(3);
        // product.push(Rc::new(gen_identity_evaluations(u_t)));
        // op_coef.push((F::one(), F::zero()));
        // product.push(Rc::clone(&t_inverse));
        // op_coef.push((F::one(), F::zero()));
        // product.push(Rc::clone(&instance.t));
        // op_coef.push((-F::one(), r));
        // poly.add_product_with_linear_op(product, &op_coef, F::one());

        // let mut product = Vec::with_capacity(2);
        // let mut op_coef = Vec::with_capacity(2);
        // product.push(Rc::new(gen_identity_evaluations(u_t)));
        // op_coef.push((F::one(), F::zero()));
        // product.push(Rc::clone(&m));
        // op_coef.push((F::one(), F::zero()));
        // poly.add_product_with_linear_op(product, &op_coef, -F::one());

        // let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
        //     .expect("sumcheck for rangecheck failed");
        // sumcheck_msg.push(sumcheck_proof.0);

        (
            LookupProof {
                sumcheck_msg,
                c_sum,
            },
            LookupOracle {
                h_vec,
                phi_vec,
                t_inverse,
                m,
            },
        )
    }

    /// Verify range check given the proof
    pub fn verify(proof: &LookupProof<F>, info: &LookupInstanceInfo) -> LookupSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verifier_as_subprotocol(&mut fs_rng, proof, info)
    }

    /// Verify addition in Zq given the proof and the verification key for bit decomposistion
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &LookupProof<F>,
        info: &LookupInstanceInfo,
    ) -> LookupSubclaim<F> {
        // TODO sample randomness via Fiat-Shamir RNG

        let chunk_size = info.block_size;

        // 1. execute sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        let poly_info = PolynomialInfo {
            max_multiplicands: chunk_size + 2,
            num_variables: info.num_vars_f,
        };
        let first_subclaim = MLSumcheck::verify_as_subprotocol(
            fs_rng,
            &poly_info,
            proof.c_sum,
            &proof.sumcheck_msg[0],
        )
        .expect("sumcheck protocol in range check failed");

        // 2. execute sumcheck for \sum_{x\in H_T} t_inverse(x) = c_sum
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: info.num_vars_t,
        };
        let second_subclaim = MLSumcheck::verify_as_subprotocol(
            fs_rng,
            &poly_info,
            proof.c_sum,
            &proof.sumcheck_msg[1],
        )
        .expect("sumcheck protocol in range check failed");

        // // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        // let poly_info = PolynomialInfo {
        //     max_multiplicands: 3,
        //     num_variables: info.num_vars_f,
        // };
        // let third_subclaim =
        //     MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::one(), &proof.sumcheck_msg[2])
        //         .expect("sumcheck protocol in range check failed");

        // // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        // let poly_info = PolynomialInfo {
        //     max_multiplicands: 3,
        //     num_variables: info.num_vars_t,
        // };
        // let forth_subclaim = MLSumcheck::verify_as_subprotocol(
        //     fs_rng,
        //     &poly_info,
        //     F::zero(),
        //     &proof.sumcheck_msg[2],
        // )
        // .expect("sumcheck protocol in range check failed");

        LookupSubclaim {
            sumcheck_points: vec![
                first_subclaim.point,
                second_subclaim.point,
                // third_subclaim.point,
                //forth_subclaim.point,
            ],
            sumcheck_expected_evaluations: vec![
                first_subclaim.expected_evaluations,
                second_subclaim.expected_evaluations,
                // third_subclaim.expected_evaluations,
                //forth_subclaim.expected_evaluations,
            ],
        }
    }
}

impl<F: Field> LookupSubclaim<F> {
    /// verify the sumcliam
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim(
        &self,
        f_vec: Vec<Rc<DenseMultilinearExtension<F>>>,
        t: Rc<DenseMultilinearExtension<F>>,
        oracle: LookupOracle<F>,
        randomness: &[F],
        info: &LookupInstanceInfo,
    ) -> bool {
        let u = &randomness[..randomness.len() - 1];
        let u_f = &u[0..info.num_vars_f];
        let u_t = &u[0..info.num_vars_t];
        let u_l = &u[0..info.l];
        let r = randomness[randomness.len() - 1];

        let block_size = info.block_size;
        let h_vec = oracle.h_vec;
        let phi_vec = oracle.phi_vec;
        let t_inverse = oracle.t_inverse;
        let m = oracle.m;

        let mut eval = F::zero();
        let point = &self.sumcheck_points[0];
        for ((h, phi_block), r) in h_vec
            .iter()
            .zip(phi_vec.chunks_exact(block_size))
            .zip(u_l.iter())
        {
            let h_eval = h.evaluate(point);

            let eq_eval = eval_identity_function(u_f, point);

            let phi_eval_block: Vec<F> = phi_block.iter().map(|phi| phi.evaluate(point)).collect();

            let sum_of_products: F = (0..phi_eval_block.len())
                .map(|i| {
                    phi_eval_block
                        .iter()
                        .enumerate()
                        .filter(|&(index, _)| index != i)
                        .map(|(_, val)| val.clone())
                        .fold(F::one(), |acc, x| acc * x) // 使用 fold 手动计算乘积
                })
                .fold(F::zero(), |acc, x| acc + x);

            let product = phi_eval_block.iter().fold(F::one(), |acc, x| acc * x);

            eval += h_eval + eq_eval * r * (h_eval * product - sum_of_products);
        }

        if eval != self.sumcheck_expected_evaluations[0] {
            return false;
        }

        // // 1. check sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        // if f_inverse.evaluate(&self.sumcheck_points[0]) != self.sumcheck_expected_evaluations[0] {
        //     return false;
        // }

        // 2. execute sumcheck for \sum_{x\in H_T} t_inverse(x) = c_sum
        // if t_inverse.evaluate(&self.sumcheck_points[1]) != self.sumcheck_expected_evaluations[1] {
        //     return false;
        // }

        // // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        // let eval_f_inverse = f_inverse.evaluate(&self.sumcheck_points[2]);
        // let eval_f = f.evaluate(&self.sumcheck_points[2]);
        // let eval_eq = eval_identity_function(u_f, &self.sumcheck_points[2]);
        // if eval_eq * eval_f_inverse * (r - eval_f) != self.sumcheck_expected_evaluations[2] {
        //     return false;
        // }

        // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        let eval_t_inverse = t_inverse.evaluate(&self.sumcheck_points[1]);
        let eval_t = t.evaluate(&self.sumcheck_points[1]);
        let eval_eq = eval_identity_function(u_t, &self.sumcheck_points[1]);
        let eval_m = m.evaluate(&self.sumcheck_points[1]);
        if t_inverse.evaluate(&self.sumcheck_points[1]) + eval_eq * (eval_t_inverse * (r - eval_t) - eval_m)
            != self.sumcheck_expected_evaluations[1]
        {
            return false;
        }

        true
    }
}

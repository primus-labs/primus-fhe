//! range check
//! document to be done
use std::marker::PhantomData;
use std::rc::Rc;

use crate::sumcheck::prover::ProverMsg;
use crate::utils::eval_identity_function;

use crate::sumcheck::MLSumcheck;
use crate::utils::gen_identity_evaluations;
use algebra::{
    AsFrom, DecomposableField, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials,
    MultilinearExtension, PolynomialInfo,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// SNARKs for range check in [T] := [0, T-1]
pub struct RangeCheck<F: Field>(PhantomData<F>);

/// proof generated by prover
pub struct RangeCheckProof<F: Field> {
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

/// subclaim returned to verifier
pub struct RangeCheckSubclaim<F: Field> {
    /// subcliams
    pub sumcheck_points: Vec<Vec<F>>,
    /// expected value returned in the last round of the sumcheck
    pub sumcheck_expected_evaluations: Vec<F>,
}

/// Stores the parameters used for range check in [T] and the inputs and witness for prover.
pub struct RangeCheckInstance<F: Field> {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars: usize,
    /// the size of range |T|
    pub range: usize,
    /// number of variables for range,
    pub num_vars_t: usize,
    /// inputs f
    pub f: Rc<DenseMultilinearExtension<F>>,
    /// introduced witness f_inverse
    pub f_inverse: DenseMultilinearExtension<F>,
    /// introduced witness t_inverse
    pub t_inverse: DenseMultilinearExtension<F>,
    /// introduced witness m
    pub m: DenseMultilinearExtension<F>,
}

/// Stores the parameters used for range check in [T] and the public info for verifier.
pub struct RangeCheckInstanceInfo {
    /// number of variables for lookups i.e. the size of log(|F|)
    pub num_vars: usize,
    /// the size of range |T|
    pub range: usize,
    /// number of variables for range,
    pub num_vars_t: usize,
}

impl<F: Field> RangeCheckInstance<F> {
    /// Extract the information of range check for verification
    #[inline]
    pub fn info(&self) -> RangeCheckInstanceInfo {
        RangeCheckInstanceInfo {
            num_vars: self.num_vars,
            num_vars_t: self.num_vars_t,
            range: self.range,
        }
    }
}

impl<F: Field> RangeCheckInstance<F> {
    /// Construct a new instance from vector
    #[inline]
    pub fn from_vec(
        f: Rc<DenseMultilinearExtension<F>>,
        f_inverse: DenseMultilinearExtension<F>,
        t_inverse: DenseMultilinearExtension<F>,
        m: DenseMultilinearExtension<F>,
        range: usize,
    ) -> Self {
        let num_vars = f.num_vars;

        Self {
            num_vars,
            range,
            num_vars_t: range.ilog(2) as usize,
            f,
            f_inverse,
            t_inverse,
            m,
        }
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        f: &Rc<DenseMultilinearExtension<F>>,
        f_inverse: &DenseMultilinearExtension<F>,
        t_inverse: &DenseMultilinearExtension<F>,
        m: &DenseMultilinearExtension<F>,
        range: usize,
    ) -> Self {
        let num_vars = f.num_vars;

        Self {
            num_vars,
            range,
            num_vars_t: range.ilog(2) as usize,
            f: f.clone(),
            f_inverse: f_inverse.clone(),
            t_inverse: t_inverse.clone(),
            m: m.clone(),
        }
    }
}

impl<F: Field + DecomposableField> RangeCheck<F> {
    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    pub fn prove(instance: &RangeCheckInstance<F>, u: &[F], r: F) -> RangeCheckProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, instance, u, r)
    }

    /// Prove addition in Zq given a, b, c, k, and the decomposed bits for a, b, and c.
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        instance: &RangeCheckInstance<F>,
        u: &[F],
        r: F,
    ) -> RangeCheckProof<F> {
        let mut sumcheck_msg = Vec::new();
        let u_f = &u[0..instance.num_vars];
        let u_t = &u[0..instance.num_vars_t];

        // // compute the counting number m
        // let mut m_evaluations = vec![F::zero(); 1<<instance.num_vars_t];
        // instance.f.iter().for_each(|item| {
        //     let idx = item.value().into() as usize;
        //     m_evaluations[idx] += F::one();
        // });
        // let m = DenseMultilinearExtension::from_evaluations_slice(instance.num_vars_t, &m_evaluations);
        let m = instance.m.clone();

        // // compute t, inverse f and inverse t
        let t = DenseMultilinearExtension::from_evaluations_vec(
            instance.num_vars_t,
            (0..instance.range)
                .map(|i| F::new(F::Value::as_from(i as f64)))
                .collect(),
        );
        // let f_inverse: DenseMultilinearExtension<F> = DenseMultilinearExtension::from_evaluations_vec(instance.num_vars, instance.f.iter().map(|item| F::one()/(r-item)).collect());
        // let t_inverse: DenseMultilinearExtension<F> = DenseMultilinearExtension::from_evaluations_vec(instance.num_vars_t, t.iter().map(|item| F::one()/(r-item)).collect());
        let f_inverse = instance.f_inverse.clone();
        let t_inverse = instance.t_inverse.clone();

        // compute c_sum = sum of f_inverse at H_F
        let c_sum = f_inverse
            .evaluations
            .iter()
            .fold(F::zero(), |sum, x| sum + x);

        // 1. execute sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars);
        let product = vec![Rc::new(f_inverse.clone())];
        let op_coef = vec![(F::one(), F::zero())];
        poly.add_product_with_linear_op(product, &op_coef, F::one());
        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        // 2. execute sumcheck for \sum_{x\in H_T} t_inverse(x) = c_sum
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_t);
        let product = vec![Rc::new(t_inverse.clone())];
        let op_coef = vec![(F::one(), F::zero())];
        poly.add_product_with_linear_op(product, &op_coef, F::one());
        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars);
        let mut product = Vec::with_capacity(3);
        let mut op_coef = Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u_f)));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::new(f_inverse.clone()));
        op_coef.push((F::one(), F::zero()));
        product.push(instance.f.clone());
        op_coef.push((-F::one(), r));
        poly.add_product_with_linear_op(product, &op_coef, F::one());
        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        let mut poly = <ListOfProductsOfPolynomials<F>>::new(instance.num_vars_t);

        let mut product = Vec::with_capacity(3);
        let mut op_coef = Vec::with_capacity(3);
        product.push(Rc::new(gen_identity_evaluations(u_t)));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::new(t_inverse));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::new(t.clone()));
        op_coef.push((-F::one(), r));
        poly.add_product_with_linear_op(product, &op_coef, F::one());

        let mut product = Vec::with_capacity(2);
        let mut op_coef = Vec::with_capacity(2);
        product.push(Rc::new(gen_identity_evaluations(u_t)));
        op_coef.push((F::one(), F::zero()));
        product.push(Rc::new(m));
        op_coef.push((F::one(), F::zero()));
        poly.add_product_with_linear_op(product, &op_coef, -F::one());

        let sumcheck_proof = MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("sumcheck for rangecheck failed");
        sumcheck_msg.push(sumcheck_proof.0);

        RangeCheckProof {
            sumcheck_msg,
            c_sum,
        }
    }

    /// Verify range check given the proof
    pub fn verify(
        proof: &RangeCheckProof<F>,
        info: &RangeCheckInstanceInfo,
    ) -> RangeCheckSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verifier_as_subprotocol(&mut fs_rng, proof, info)
    }

    /// Verify addition in Zq given the proof and the verification key for bit decomposistion
    /// This function does the same thing as `prove`, but it uses a `Fiat-Shamir RNG` as the transcript/to generate the
    /// verifier challenges.
    pub fn verifier_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &RangeCheckProof<F>,
        info: &RangeCheckInstanceInfo,
    ) -> RangeCheckSubclaim<F> {
        // TODO sample randomness via Fiat-Shamir RNG

        // 1. execute sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        let poly_info = PolynomialInfo {
            max_multiplicands: 1,
            num_variables: info.num_vars,
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
            max_multiplicands: 1,
            num_variables: info.num_vars_t,
        };
        let second_subclaim = MLSumcheck::verify_as_subprotocol(
            fs_rng,
            &poly_info,
            proof.c_sum,
            &proof.sumcheck_msg[1],
        )
        .expect("sumcheck protocol in range check failed");

        // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: info.num_vars,
        };
        let third_subclaim =
            MLSumcheck::verify_as_subprotocol(fs_rng, &poly_info, F::one(), &proof.sumcheck_msg[2])
                .expect("sumcheck protocol in range check failed");

        // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: info.num_vars_t,
        };
        let forth_subclaim = MLSumcheck::verify_as_subprotocol(
            fs_rng,
            &poly_info,
            F::zero(),
            &proof.sumcheck_msg[3],
        )
        .expect("sumcheck protocol in range check failed");

        RangeCheckSubclaim {
            sumcheck_points: vec![
                first_subclaim.point,
                second_subclaim.point,
                third_subclaim.point,
                forth_subclaim.point,
            ],
            sumcheck_expected_evaluations: vec![
                first_subclaim.expected_evaluations,
                second_subclaim.expected_evaluations,
                third_subclaim.expected_evaluations,
                forth_subclaim.expected_evaluations,
            ],
        }
    }
}

impl<F: Field> RangeCheckSubclaim<F> {
    /// verify the sumcliam
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_subclaim(
        &self,
        f: Rc<DenseMultilinearExtension<F>>,
        f_inverse: &DenseMultilinearExtension<F>,
        t_inverse: &DenseMultilinearExtension<F>,
        t: &DenseMultilinearExtension<F>,
        m: &DenseMultilinearExtension<F>,
        u: &[F],
        r: F,
        info: &RangeCheckInstanceInfo,
    ) -> bool {
        let u_f = &u[0..info.num_vars];
        let u_t = &u[0..info.num_vars_t];

        // 1. check sumcheck for \sum_{x\in H_F} f_inverse(x) = c_sum
        if f_inverse.evaluate(&self.sumcheck_points[0]) != self.sumcheck_expected_evaluations[0] {
            return false;
        }

        // 2. execute sumcheck for \sum_{x\in H_T} t_inverse(x) = c_sum
        if t_inverse.evaluate(&self.sumcheck_points[1]) != self.sumcheck_expected_evaluations[1] {
            return false;
        }

        // 3. execute sumcheck for \sum_{x\in H_F} eq(x, u) f_inverse(x) (r - f(x)) = 1
        let eval_f_inverse = f_inverse.evaluate(&self.sumcheck_points[2]);
        let eval_f = f.evaluate(&self.sumcheck_points[2]);
        let eval_eq = eval_identity_function(u_f, &self.sumcheck_points[2]);
        if eval_eq * eval_f_inverse * (r - eval_f) != self.sumcheck_expected_evaluations[2] {
            return false;
        }

        // 4. execute sumcheck for \sum_{x\in H_T} eq(x, u) (t_inverse(x) (r - t(x)) - m(x)) = 0
        let eval_t_inverse = t_inverse.evaluate(&self.sumcheck_points[3]);
        let eval_t = t.evaluate(&self.sumcheck_points[3]);
        let eval_eq = eval_identity_function(u_t, &self.sumcheck_points[3]);
        let eval_m = m.evaluate(&self.sumcheck_points[3]);
        if eval_eq * (eval_t_inverse * (r - eval_t) - eval_m)
            != self.sumcheck_expected_evaluations[3]
        {
            return false;
        }

        true
    }
}
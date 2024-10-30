use algebra::{
    utils::Transcript, BabyBear, DenseMultilinearExtension, Field, FieldUniformSampler,
    ListOfProductsOfPolynomials, MultilinearExtension,
};
use rand::prelude::*;
use rand_distr::Distribution;
use serde::Serialize;
use std::rc::Rc;
use zkp::sumcheck::IPForMLSumcheck;
use zkp::sumcheck::MLSumcheck;

// field type
type FF = BabyBear;

fn random_product<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands: usize,
    rng: &mut R,
) -> (Vec<Rc<DenseMultilinearExtension<F>>>, F) {
    let mut multiplicands = Vec::with_capacity(num_multiplicands);
    for _ in 0..num_multiplicands {
        multiplicands.push(Vec::with_capacity(1 << nv));
    }
    let mut sum = F::zero();

    let uniform_sampler = FieldUniformSampler::new();
    for _ in 0..(1 << nv) {
        let mut product = F::one();
        for multiplicand in &mut multiplicands {
            let val = uniform_sampler.sample(rng);
            multiplicand.push(val);
            product *= val;
        }
        sum += product;
    }

    (
        multiplicands
            .into_iter()
            .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
            .collect(),
        sum,
    )
}

fn random_list_of_products<F: Field, R: RngCore>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    rng: &mut R,
) -> (ListOfProductsOfPolynomials<F>, F) {
    let mut sum = F::zero();
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    let uniform_sampler = FieldUniformSampler::new();
    for _ in 0..num_products {
        let num_multiplicands: usize =
            rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
        let (product, product_sum) = random_product(nv, num_multiplicands, rng);
        let coefficient = uniform_sampler.sample(rng);
        poly.add_product(product.into_iter(), coefficient);
        sum += product_sum * coefficient;
    }

    (poly, sum)
}

fn test_protocol<F: Field + Serialize>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
) {
    let mut rng = thread_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<F, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let mut prover_state = IPForMLSumcheck::prover_init(&poly);
    let mut verifier_state = IPForMLSumcheck::verifier_init(&poly_info);
    let mut verifier_msg = None;

    let mut verifier_trans = Transcript::<F>::new();
    for _ in 0..poly.num_variables {
        let prover_message = IPForMLSumcheck::prove_round(&mut prover_state, &verifier_msg);
        verifier_msg = IPForMLSumcheck::verify_round(
            &prover_message,
            &mut verifier_state,
            &mut verifier_trans,
        );
    }
    let subclaim = IPForMLSumcheck::check_and_generate_subclaim(verifier_state, asserted_sum)
        .expect("fail to generate subclaim");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluations,
        "wrong subclaim"
    );
}

fn test_polynomial(nv: usize, num_multiplicands_range: (usize, usize), num_products: usize) {
    let mut rng = thread_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<FF, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let mut trans = Transcript::<FF>::new();
    let (proof, _) = MLSumcheck::prove(&mut trans, &poly).expect("fail to prove");

    let mut trans = Transcript::<FF>::new();
    let subclaim =
        MLSumcheck::verify(&mut trans, &poly_info, asserted_sum, &proof).expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluations,
        "wrong subclaim"
    );
}

fn test_polynomial_as_subprotocol<F: Field + Serialize>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    prover_trans: &mut Transcript<F>,
    verifier_trans: &mut Transcript<F>,
) {
    let mut rng = thread_rng();
    let (poly, asserted_sum) =
        random_list_of_products::<F, _>(nv, num_multiplicands_range, num_products, &mut rng);
    let poly_info = poly.info();
    let (proof, prover_state) = MLSumcheck::prove(prover_trans, &poly).expect("fail to prove");
    let subclaim = MLSumcheck::verify(verifier_trans, &poly_info, asserted_sum, &proof)
        .expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluations,
        "wrong subclaim"
    );
    assert_eq!(prover_state.randomness, subclaim.point);
}

#[test]
fn test_trivial_polynomial() {
    let nv = 1;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    for _ in 0..10 {
        test_protocol::<FF>(nv, num_multiplicands_range, num_products);
        test_polynomial(nv, num_multiplicands_range, num_products);

        let mut prover_trans = Transcript::new();
        let mut verifier_trans = Transcript::new();

        test_polynomial_as_subprotocol::<FF>(
            nv,
            num_multiplicands_range,
            num_products,
            &mut prover_trans,
            &mut verifier_trans,
        )
    }
}

#[test]
fn test_normal_polynomial() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    for _ in 0..10 {
        test_protocol::<FF>(nv, num_multiplicands_range, num_products);
        test_polynomial(nv, num_multiplicands_range, num_products);

        let mut prover_trans = Transcript::new();
        let mut verifier_trans = Transcript::new();

        test_polynomial_as_subprotocol::<FF>(
            nv,
            num_multiplicands_range,
            num_products,
            &mut prover_trans,
            &mut verifier_trans,
        )
    }
}

#[test]
#[should_panic]
fn test_normal_polynomial_different_transcript_fails() {
    let nv = 12;
    let num_multiplicands_range = (4, 9);
    let num_products = 5;

    let mut prover_trans = Transcript::new();
    let mut verifier_trans = Transcript::new();
    verifier_trans.append_message(b"label", b"different transcript");

    test_polynomial_as_subprotocol::<FF>(
        nv,
        num_multiplicands_range,
        num_products,
        &mut prover_trans,
        &mut verifier_trans,
    )
}

#[test]
#[should_panic]
fn zero_polynomial_should_error() {
    let nv = 0;
    let num_multiplicands_range = (4, 13);
    let num_products = 5;

    test_polynomial(nv, num_multiplicands_range, num_products);
}

#[test]
fn test_extract_sum() {
    let mut rng = thread_rng();
    let (poly, asserted_sum) = random_list_of_products::<FF, _>(8, (3, 4), 3, &mut rng);

    let mut trans = Transcript::<FF>::new();
    let (proof, _) = MLSumcheck::prove(&mut trans, &poly).expect("fail to prove");
    assert_eq!(MLSumcheck::extract_sum(&proof), asserted_sum);
}

#[test]
/// Test that the memory usage of shared-reference is linear to number of unique MLExtensions
/// instead of total number of multiplicands.
fn test_shared_reference() {
    let mut rng = thread_rng();
    let ml_extensions: Vec<_> = (0..5)
        .map(|_| Rc::new(DenseMultilinearExtension::<FF>::random(8, &mut rng)))
        .collect();
    let mut poly = ListOfProductsOfPolynomials::new(8);

    let uniform_sampler = <FieldUniformSampler<FF>>::new();
    poly.add_product(
        vec![
            ml_extensions[0].clone(),
            ml_extensions[1].clone(),
            ml_extensions[2].clone(),
        ],
        uniform_sampler.sample(&mut rng),
    );
    poly.add_product(
        vec![
            ml_extensions[1].clone(),
            ml_extensions[1].clone(),
            ml_extensions[3].clone(),
        ],
        uniform_sampler.sample(&mut rng),
    );
    poly.add_product(
        vec![
            ml_extensions[2].clone(),
            ml_extensions[3].clone(),
            ml_extensions[2].clone(),
        ],
        uniform_sampler.sample(&mut rng),
    );
    poly.add_product(
        vec![ml_extensions[4].clone(), ml_extensions[4].clone()],
        uniform_sampler.sample(&mut rng),
    );
    poly.add_product(
        vec![ml_extensions[0].clone()],
        uniform_sampler.sample(&mut rng),
    );

    assert_eq!(poly.flattened_ml_extensions.len(), 5);

    // test memory usage for prover
    let prover = IPForMLSumcheck::prover_init(&poly);
    assert_eq!(prover.flattened_ml_extensions.len(), 5);
    drop(prover);

    let poly_info = poly.info();
    let mut trans = Transcript::<FF>::new();
    let (proof, _) = MLSumcheck::prove(&mut trans, &poly).expect("fail to prove");
    let asserted_sum = MLSumcheck::extract_sum(&proof);

    let mut trans = Transcript::<FF>::new();
    let subclaim =
        MLSumcheck::verify(&mut trans, &poly_info, asserted_sum, &proof).expect("fail to verify");
    assert!(
        poly.evaluate(&subclaim.point) == subclaim.expected_evaluations,
        "wrong subclaim"
    );
}

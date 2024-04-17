use algebra::{derive::*, DenseMultilinearExtension, FieldUniformSampler, MultilinearExtension};
use pcs::{
    multilinear::brakedown::{BrakedownProtocol, BrakedownProver, BrakedownVerifier},
    utils::code::{BrakedownCodeSpec, LinearCode},
};
use rand::Rng;

#[derive(Field)]
#[modulus = 32] // field_size_bit = 5
pub struct FF32(u64);

fn main() {
    // sample a polynomial
    let num_vars = 4;
    let evaluations: Vec<FF32> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();
    println!("evaluations: {:?}", evaluations);
    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    // randomness
    let setup_rng = rand::thread_rng(); // public randomness
    let verifier_rng = rand::thread_rng(); // private randomness of the verifier or public randomness from fiat-shamir transformation

    // specification of the brakedown protocol
    let spec = BrakedownCodeSpec::new(128.0, 0.1195, 0.0284, 1.9, 5, 1);

    // Setup

    // prover and verifier transparently reach a consensus of field, variables number, pcs specification
    let (pp, vp) = BrakedownProtocol::<FF32>::setup(num_vars, 4, spec, setup_rng);
    println!(
        "message_len: {:?}\ncodeword_len: {:?}",
        &pp.brakedown.message_len(),
        &pp.brakedown.codeword_len()
    );
    let mut prover = BrakedownProver::new(pp);
    let mut verifier = BrakedownVerifier::new(vp, verifier_rng);

    // Commitment

    // prover commits the polynomial and sends the commitment to the verifier
    let root = prover.commit_poly(&poly);
    println!("root: {:?}", &root);
    // verifier receives the commitment
    verifier.receive_root(root);

    // Proximity Check

    // verifier generates a random challenge
    let challenge = verifier.random_challenge();
    println!("challenge: {:?}", &challenge);
    // prover answers the challenge
    let answer = prover.answer_challenge(challenge);
    println!("answer: {:?}", &answer);
    // the verifier receives the answer
    verifier.receive_answer(answer);
    //println!("encoded answer: {:?}", verifier.answer);
    // verifier generates a set of random opening queries
    let queries = verifier.random_queries();
    // prover answers the opening queries
    let (merkle_paths, columns) = prover.answer_queries(queries);
    println!("merkle_paths: {:?}\ncolunms: {:?}", &merkle_paths, &columns);
    // verifier checks whether the answer is consistent with the queries
    verifier.check_answer(merkle_paths, columns);

    // Consistency Check

    // verifier generates the tensor of the evaluation point
    let point: Vec<FF32> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();
    //let point = vec![FF32::ONE, FF32::ZERO, FF32::ZERO, FF32::ZERO];
    println!("point: {:?}", point);
    // verifier challenge prover by the tensor
    let tensor = verifier.tensor_decompose(&point);
    println!("tensor: {:?}", &tensor);
    // prover answers the challenge by product of the tensor and the polynomial matrix
    let product = prover.answer_challenge(&tensor);
    println!("product: {:?}", &product);
    // the verifier receives the product
    verifier.receive_answer(product);
    //println!("encoded product: {:?}", verifier.answer);
    // verifier generates a set of random opening queries
    let queries = verifier.random_queries();
    println!("queries: {:?}", &queries);
    // prover answers the opening queries
    let (merkle_paths, columns) = prover.answer_queries(queries);
    println!("merkle_paths: {:?}\ncolunms: {:?}", &merkle_paths, &columns);
    // verifier checks whether the answer is consistent with the queries
    verifier.check_answer(merkle_paths, columns);

    // Final Evaluation

    // verifier computes the residual product operation
    let pcs_evaluation = verifier.residual_product();
    println!("pcs evalution: {:?}", &pcs_evaluation);
    // true evalutaions
    let true_evaluation = poly.evaluate(&point);
    println!("true evalution: {:?}", &true_evaluation);
    assert!(true_evaluation == pcs_evaluation);
}

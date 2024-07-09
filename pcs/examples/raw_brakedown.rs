// use algebra::{derive::*, DenseMultilinearExtension, FieldUniformSampler, MultilinearExtension};
// use pcs::{
//     multilinear::brakedown::{prover::PcsProver, verifier::PcsVerifier, BrakedownProtocol},
//     utils::code::{ExpanderCode, ExpanderCodeSpec, LinearCode},
// };
// use rand::Rng;
// use sha3::Sha3_256;

// #[derive(Field)]
// #[modulus = 1152921504606846883] // field_size_bit = 5
// pub struct FF(u64);

// fn main() {
//     // sample a polynomial
//     let num_vars = 15;
//     let evaluations: Vec<FF> = rand::thread_rng()
//         .sample_iter(FieldUniformSampler::new())
//         .take(1 << num_vars)
//         .collect();
//     let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

//     // public randomness
//     let setup_rng = rand::thread_rng();
//     // private randomness of the verifier or public randomness from fiat-shamir transformation
//     let verifier_rng = rand::thread_rng();

//     // specification of the brakedown protocol
//     let spec = ExpanderCodeSpec::new(32, 0.1195, 0.0284, 1.9, 60, 10);

//     // Setup

//     let protocol = BrakedownProtocol::<FF, ExpanderCode<FF>, Sha3_256>::new(
//         128,
//         num_vars,
//         (1 << num_vars) >> 1,
//         spec,
//         setup_rng,
//     );
//     // prover and verifier transparently reach a consensus of field, variables number, pcs specification
//     let (pp, vp) = protocol.setup();
//     println!(
//         "message_len: {:?}\ncodeword_len: {:?}",
//         &pp.code.message_len(),
//         &pp.code.codeword_len()
//     );
//     let mut prover = PcsProver::new(pp);
//     let mut verifier = PcsVerifier::new(vp, verifier_rng);

//     // Commitment

//     // prover commits the polynomial and sends the commitment to the verifier
//     let root = prover.commit_poly(&poly);

//     // verifier receives the commitment
//     verifier.receive_root(&root);

//     // Proximity Check

//     // verifier generates a random challenge
//     let challenge = verifier.random_challenge();

//     // prover answers the challenge
//     let answer: Vec<FF> = prover.answer_challenge(challenge);

//     // the verifier receives the answer
//     verifier.receive_answer(&answer);

//     // verifier generates a set of random opening queries
//     let queries = verifier.random_queries();

//     // prover answers the opening queries
//     let (merkle_paths, columns) = prover.answer_queries(queries);

//     // verifier checks whether the answer is consistent with the queries
//     verifier.check_answer(&merkle_paths, &columns);

//     // Consistency Check

//     // verifier generates the tensor of the evaluation point
//     let point: Vec<FF> = rand::thread_rng()
//         .sample_iter(FieldUniformSampler::new())
//         .take(num_vars)
//         .collect();

//     // verifier challenge prover by the tensor
//     let tensor = verifier.tensor_decompose(&point);

//     // prover answers the challenge by product of the tensor and the polynomial matrix
//     let product = prover.answer_challenge(&tensor);

//     // the verifier receives the product
//     verifier.receive_answer(&product);

//     // verifier generates a set of random opening queries
//     let queries = verifier.random_queries();

//     // prover answers the opening queries
//     let (merkle_paths, columns) = prover.answer_queries(queries);

//     // verifier checks whether the answer is consistent with the queries
//     verifier.check_answer(&merkle_paths, &columns);

//     // Final Evaluation

//     // verifier computes the residual product operation
//     let pcs_evaluation = verifier.residual_product();
//     println!("pcs evalution: {:?}", &pcs_evaluation);

//     // true evalutaions
//     let true_evaluation = poly.evaluate(&point);
//     println!("true evalution: {:?}", &true_evaluation);

//     // check the correctness
//     assert!(true_evaluation == pcs_evaluation);
// }

fn main(){
    
}
use algebra::{derive::*, DenseMultilinearExtension, Field, FieldUniformSampler};
use criterion::{criterion_group, criterion_main, Criterion};
use pcs::{
    multilinear::brakedown::{prover::PcsProver, verifier::PcsVerifier, BrakedownProtocol},
    utils::code::{LinearCode, ExpanderCodeSpec},
};
use rand::Rng;
use std::mem;

#[derive(Field, Prime, NTT)]
#[modulus = 63]
pub struct FF(u64);

fn main() {
    // sample a polynomial
    let num_vars = 6;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();
    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);
    let point: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();
    println!(
        "polynomial size: {} coefficients, {} variables",
        1 << num_vars,
        num_vars
    );

    // randomness
    let setup_rng = rand::thread_rng(); // public randomness
    let verifier_rng = rand::thread_rng(); // private randomness of the verifier or public randomness from fiat-shamir transformation
                                           // specification of the brakedown protocol
    let code_spec: ExpanderCodeSpec = ExpanderCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);

    // Setup

    // find opt message length
    let mut opt_message_len = 0;
    let mut min_proof_size = usize::MAX;
    for log_message_len in 4..num_vars {
        let message_len = 1 << log_message_len;
        let setup_rng = rand::thread_rng();
        let protocol =
            BrakedownProtocol::<FF>::new(128, num_vars, message_len, code_spec.clone(), setup_rng);
        if protocol.proof_size() < min_proof_size {
            opt_message_len = message_len;
            min_proof_size = protocol.proof_size();
        }
    }

    let message_len = opt_message_len;
    println!("message_len: {}", message_len);

    // setup

    let protocol = BrakedownProtocol::<FF>::new(128, num_vars, message_len, code_spec, setup_rng);
    // prover and verifier transparently reach a consensus of field, variables number, pcs specification
    let (pp, vp) = protocol.setup();
    println!(
        "message_len(row_len): {:?}\ncodeword_len: {:?}",
        &pp.code.message_len(),
        &pp.code.codeword_len()
    );
    println!("row_num: {}", pp.num_rows);
    let mut prover = PcsProver::new(pp);
    let mut verifier = PcsVerifier::new(vp, verifier_rng);
    let first_queries = verifier.random_queries().clone();
    let challenge = verifier.random_challenge().clone();
    let tensor = verifier.tensor_decompose(&point).clone();
    let second_queries = verifier.random_queries().clone();
    println!("number of queries: {}", prover.pp.code.num_queries());

    
    // proof size
    let root = prover.commit_poly(&poly);
    let answer = prover.answer_challenge(&challenge);
    let (first_merkle_paths, first_columns) = prover.answer_queries(&first_queries);
    let product = prover.answer_challenge(&tensor);
    let (second_merkle_paths, second_columns) = prover.answer_queries(&second_queries);

    let mut proof_len = 0;
    let mut hash_len = 0;

    proof_len += mem::size_of_val(&root);
    proof_len += mem::size_of_val(&answer);
    hash_len += mem::size_of_val(&first_merkle_paths);
    proof_len += mem::size_of_val(&first_columns);
    proof_len += mem::size_of_val(&product);
    hash_len += mem::size_of_val(&second_merkle_paths);
    proof_len += mem::size_of_val(&second_columns);

    println!("{:?}",first_columns);
    println!("{}",first_columns.len());
    println!("{}",first_columns[0].len());


    // let raw_proof_size = mem::size_of_val(&(
    //     root,
    //     answer,
    //     first_merkle_paths.clone(),
    //     first_columns.clone(),
    //     product,
    //     second_merkle_paths.clone(),
    //     second_columns.clone(),
    // ));

    let field_size = mem::size_of_val(&FF::ZERO);
    println!("FF size: {} bytes", field_size);

    println!("{:?}", prover.matrix);
    
    println!("proof size: {} bytes", proof_len);
    println!("hash size: {} bytes", hash_len);
    

    // verifier time

    let root = prover.commit_poly(&poly);
    let answer = prover.answer_challenge(&challenge);
    let (first_merkle_paths, first_columns) = prover.answer_queries(&first_queries);
    let product = prover.answer_challenge(&tensor);
    //let (second_merkle_paths, second_columns) = prover.answer_queries(&second_queries);
}
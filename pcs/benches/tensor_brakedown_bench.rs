use algebra::{derive::*, DenseMultilinearExtension, FieldUniformSampler};
use criterion::{criterion_group, criterion_main, Criterion};
use pcs::{
    multilinear::brakedown::{prover::PcsProver, verifier::PcsVerifier, BrakedownProtocol},
    utils::code::{LinearCode, LinearTimeCodeSpec},
};
use rand::Rng;
use std::mem;

#[derive(Field, Prime, NTT)]
#[modulus = 1152921504606846883]
pub struct FF(u64);

pub fn criterion_benchmark(c: &mut Criterion) {
    // sample a polynomial
    let num_vars = 20;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();
    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);
    println!(
        "polynomial size: {} coefficients, {} variables",
        1 << num_vars,
        num_vars
    );

    // randomness
    let setup_rng = rand::thread_rng(); // public randomness
    let verifier_rng = rand::thread_rng(); // private randomness of the verifier or public randomness from fiat-shamir transformation
    // specification of the brakedown protocol
    let code_spec = LinearTimeCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);

    // Setup

    // find opt message length
    let mut opt_message_len = 0;
    let mut min_proof_size = usize::MAX;
    for log_message_len in 4..num_vars {
        let message_len = 1 << log_message_len;
        let setup_rng = rand::thread_rng();
        let protocol =BrakedownProtocol::<FF>::new(128, num_vars, message_len, code_spec.clone(), setup_rng);
        if protocol.proof_size() < min_proof_size {
            opt_message_len = message_len;
            min_proof_size = protocol.proof_size();
        }
    }

    let message_len = opt_message_len;
    println!("message_len: {}", message_len);

    // setup

    let protocol =
        BrakedownProtocol::<FF>::new(128, num_vars, message_len, code_spec, setup_rng);
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
    let queries = verifier.random_queries().clone();
    let tensor = verifier.random_tensor();
    println!("number of queries: {}", prover.pp.code.num_queries());

    let mut group = c.benchmark_group("brakedown pcs");

    group.bench_function(&format!("prover overall time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            prover.commit_poly(&poly);
            prover.answer_tensor(&tensor);
            prover.answer_queries(&queries);
        })
    });

    group.bench_function(&format!("prover commit time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            prover.commit_poly(&poly);
        })
    });

    group.bench_function(&format!("prover answer tensor time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            prover.answer_tensor(&tensor);
        })
    });

    group.bench_function(&format!("prover answer queries time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            prover.answer_queries(&queries);
        })
    });


    // proof size
    let root = prover.commit_poly(&poly);
    let answer = prover.answer_tensor(&tensor);
    let (first_merkle_paths, first_columns) = prover.answer_queries(&queries);
    let product = prover.answer_challenge(&tensor);

    let raw_proof_size = mem::size_of_val(&(
        root,
        answer,
        first_merkle_paths.clone(),
        first_columns.clone(),
        product,
    ));
    println!("raw proof size: {} bytes", raw_proof_size);

    // verifier time

    let root = prover.commit_poly(&poly);
    let answer = prover.answer_tensor(&tensor);
    let (merkle_paths, columns) = prover.answer_queries(&queries);

    group.bench_function(&format!("verify overall time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            verifier.receive_root(&root);
            verifier.random_tensor();
            verifier.receive_answer(&answer);
            verifier.random_queries();
            verifier.check_answer(&merkle_paths, &columns);
        })
    });

    group.bench_function(&format!("verify random challenge time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            verifier.random_tensor();
        })
    });

    group.bench_function(&format!("verify receive answer time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            verifier.receive_answer(&answer);
        })
    });

    group.bench_function(&format!("verify random queries time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            verifier.random_queries();
        })
    });

    group.bench_function(&format!("verify check answer time of poly of num_vars {}", num_vars), |b| {
        b.iter(|| {
            verifier.check_answer(&merkle_paths, &columns);
        })
    });

    group.finish();
}



criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

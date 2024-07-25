use std::time::Instant;

use algebra::{
    derive::Field, utils::Transcript, DenseMultilinearExtension, FieldUniformSampler,
    MultilinearExtension,
};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

#[derive(Field)]
#[modulus = 1152921504606846883]
pub struct FF(u64);

fn main() {
    let num_vars = 20;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    let code_spec = ExpanderCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);

    type Hash = Sha256;

    let start = Instant::now();
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec>::setup(
        num_vars,
        Some(code_spec),
    );
    println!("setup time: {:?} ms", start.elapsed().as_millis());

    let mut trans = Transcript::<FF>::new();

    let start = Instant::now();
    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec>::commit(&pp, &poly);
    println!("commit time: {:?} ms", start.elapsed().as_millis());

    let point: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let start = Instant::now();
    let proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec>::open(
        &pp, &comm, &state, &point, &mut trans,
    );
    println!("open time: {:?} ms", start.elapsed().as_millis());

    let eval = poly.evaluate(&point);

    let mut trans = Transcript::<FF>::new();

    let start = Instant::now();
    let check = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec>::verify(
        &pp, &comm, &point, eval, &proof, &mut trans,
    );
    println!("verify time: {:?} ms", start.elapsed().as_millis());

    println!("proof size: {:?} Bytes", proof.to_bytes().unwrap().len());

    assert!(check);
}

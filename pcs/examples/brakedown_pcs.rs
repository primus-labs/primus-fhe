use std::time::Instant;

use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, FieldUniformSampler,
};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn main() {
    let num_vars = 24;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.9, BASE_FIELD_BITS, 10);

    let start = Instant::now();
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars,
        Some(code_spec),
    );
    println!("setup time: {:?} ms", start.elapsed().as_millis());

    let mut trans = Transcript::<EF>::new();

    let start = Instant::now();
    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);
    println!("commit time: {:?} ms", start.elapsed().as_millis());

    let point: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let start = Instant::now();
    let proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp, &comm, &state, &point, &mut trans,
    );
    println!("open time: {:?} ms", start.elapsed().as_millis());

    let eval = poly.evaluate_ext(&point);

    let mut trans = Transcript::<EF>::new();

    let start = Instant::now();
    let check = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp, &comm, &point, eval, &proof, &mut trans,
    );
    println!("verify time: {:?} ms", start.elapsed().as_millis());

    println!("proof size: {:?} Bytes", proof.to_bytes().unwrap().len());

    assert!(check);
}

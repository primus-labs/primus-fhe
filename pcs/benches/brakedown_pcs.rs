use std::time::Duration;

use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, FieldUniformSampler,
};
use criterion::{criterion_group, criterion_main, Criterion};
use pcs::{
    multilinear::{
        BrakedownCommitmentState, BrakedownOpenProof, BrakedownPCS, BrakedownPolyCommitment,
    },
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

pub fn criterion_benchmark(c: &mut Criterion) {
    let num_vars = 24;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.9, BASE_FIELD_BITS, 10);

    let point: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let eval = poly.evaluate_ext(&point);

    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars,
        Some(code_spec),
    );

    let mut trans = Transcript::<EF>::new();
    let mut comm = BrakedownPolyCommitment::default();
    let mut state = BrakedownCommitmentState::default();
    let mut proof = BrakedownOpenProof::default();

    c.bench_function(&format!("num_vars: {}, commit time: ", num_vars), |b| {
        b.iter(|| {
            (comm, state) =
                BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly)
        })
    });

    c.bench_function(&format!("num_vars: {}, opening time: ", num_vars), |b| {
        b.iter(|| {
            proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
                &pp, &comm, &state, &point, &mut trans,
            )
        })
    });

    c.bench_function(
        &format!("num_vars: {}, verification time: ", num_vars),
        |b| {
            b.iter(|| {
                BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
                    &pp, &comm, &point, eval, &proof, &mut trans,
                )
            })
        },
    );
}

fn configure() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::new(5, 0))
        .measurement_time(Duration::new(10, 0))
        .sample_size(10)
}

criterion_group! {
    name = benches;
    config = configure();
    targets = criterion_benchmark
}

criterion_main!(benches);

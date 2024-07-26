use algebra::{
    derive::Field,
    utils::{Prg, Transcript},
    DenseMultilinearExtension, FieldUniformSampler, MultilinearExtension,
};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha3::Sha3_256;

#[derive(Field)]
#[modulus = 1152921504606846883]
pub struct FF(u64);

#[test]
fn pcs_test() {
    let num_vars = 10;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    let mut rng = Prg::new();

    let code_spec = ExpanderCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);

    let pp = BrakedownPCS::<FF, Sha3_256, ExpanderCode<FF>, ExpanderCodeSpec>::setup(
        num_vars,
        Some(code_spec),
        &mut rng,
    );

    let mut trans = Transcript::<FF>::new();

    let (comm, state) =
        BrakedownPCS::<FF, Sha3_256, ExpanderCode<FF>, ExpanderCodeSpec>::commit(&pp, &poly);

    let point: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let proof = BrakedownPCS::<FF, Sha3_256, ExpanderCode<FF>, ExpanderCodeSpec>::open(
        &pp, &comm, &state, &point, &mut trans,
    );

    let eval = poly.evaluate(&point);

    let mut trans = Transcript::<FF>::new();

    let check = BrakedownPCS::<FF, Sha3_256, ExpanderCode<FF>, ExpanderCodeSpec>::verify(
        &pp, &comm, &point, eval, &proof, &mut trans,
    );

    assert!(check);
}

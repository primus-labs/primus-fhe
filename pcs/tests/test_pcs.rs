use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, FieldUniformSampler,
};
use pcs::{
    multilinear::{brakedown::BrakedownPCS, BrakedownOpenProof},
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

type FF = BabyBear;
#[test]
fn pcs_test() {
    let num_vars = 10;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    type Hash = Sha256;

    let code_spec = ExpanderCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);

    let pp =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, BabyBearExetension>::setup(
            num_vars,
            Some(code_spec),
        );

    let mut trans = Transcript::<FF>::new();

    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, BabyBearExetension>::commit(
            &pp, &poly,
        );

    let point: Vec<BabyBearExetension> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let proof =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, BabyBearExetension>::open(
            &pp, &comm, &state, &point, &mut trans,
        );

    let buffer = proof.to_bytes().unwrap();

    let eval = poly.evaluate_ext(&point);

    let mut trans = Transcript::<FF>::new();

    let proof = BrakedownOpenProof::<FF, Hash, BabyBearExetension>::from_bytes(&buffer).unwrap();

    let check =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, BabyBearExetension>::verify(
            &pp, &comm, &point, eval, &proof, &mut trans,
        );

    assert!(check);
}

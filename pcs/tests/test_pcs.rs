use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, FieldUniformSampler,
};
use pcs::{
    multilinear::{brakedown::BrakedownPCS, BrakedownOpenProof, BrakedownOpenProofGeneral},
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::Rng;
use sha2::Sha256;

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

#[test]
fn pcs_test() {
    let num_vars = 10;
    let evaluations: Vec<FF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    // let code_spec = ExpanderCodeSpec::new(128, 0.1195, 0.0284, 1.9, 60, 10);
    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0284, 1.9, BASE_FIELD_BITS, 10);

    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars,
        Some(code_spec),
    );

    let mut trans = Transcript::<EF>::new();

    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);

    let point: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp, &comm, &state, &point, &mut trans,
    );

    let buffer = proof.to_bytes().unwrap();

    let eval = poly.evaluate_ext(&point);

    let mut trans = Transcript::<EF>::new();

    let proof = BrakedownOpenProof::<FF, Hash, EF>::from_bytes(&buffer).unwrap();

    let check = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp, &comm, &point, eval, &proof, &mut trans,
    );

    assert!(check);

    // Commit extension field polynomial.
    let evaluations: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(1 << num_vars)
        .collect();

    let ext_poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    let mut trans = Transcript::<EF>::new();

    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit_ef(&pp, &ext_poly);

    let point: Vec<EF> = rand::thread_rng()
        .sample_iter(FieldUniformSampler::new())
        .take(num_vars)
        .collect();

    let proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open_ef(
        &pp, &comm, &state, &point, &mut trans,
    );

    let buffer = proof.to_bytes().unwrap();

    let eval = ext_poly.evaluate(&point);

    let mut trans = Transcript::<EF>::new();

    let proof = BrakedownOpenProofGeneral::<EF, Hash>::from_bytes(&buffer).unwrap();

    let check = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify_ef(
        &pp, &comm, &point, eval, &proof, &mut trans,
    );

    assert!(check);
}

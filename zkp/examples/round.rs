use algebra::utils::Transcript;
use algebra::{BabyBear, BabyBearExetension, DenseMultilinearExtension};
use algebra::{Field, FieldUniformSampler};
use pcs::multilinear::BrakedownPCS;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use zkp::piop::round::{RoundParams, RoundProof, RoundProver, RoundVerifier};
use zkp::piop::{BitDecompositionInstanceInfo, RoundInstance};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = DefaultFieldU32: denotes the ciphertext modulus in RLWE
const LOG_DIM_RLWE: usize = 10;

const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
const FT: u32 = 1024; // message space
const LOG_FT: usize = FT.next_power_of_two().ilog2() as usize;
const BASE_LEN: u32 = 1;
const FK: u32 = (FP - 1) / (2 * FT);
const LOG_2FK: u32 = (2 * FK).next_power_of_two().ilog2();
const DELTA: u32 = (1 << LOG_2FK) - (2 * FK);

#[inline]
fn decode(c: FF) -> u32 {
    (c.value() as f64 * FT as f64 / FP as f64).round() as u32 % FT
}

fn generate_instance(num_vars: usize) -> RoundInstance<FF> {
    let q = FF::new(FT);
    let k = FF::new(FK);
    let k_bits_len = LOG_2FK as usize;
    let delta: FF = FF::new(DELTA);

    let base_len = BASE_LEN as usize;
    let base: FF = FF::new(1 << base_len);

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));
    let output = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        input.iter().map(|x| FF::new(decode(*x))).collect(),
    ));
    let output_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 2,
    };

    let offset_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    <RoundInstance<FF>>::new(
        num_vars,
        q,
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    )
}
fn main() {
    // Generate 1 instance to be proved, containing N = 2^num_vars round relation to be proved
    let num_vars = LOG_DIM_RLWE;
    let instance = generate_instance(num_vars);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = instance.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = RoundParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let start = Instant::now();
    params.setup(&instance.info(), code_spec);
    println!("round setup time: {:?} ms", start.elapsed().as_millis());

    // Prover.
    let floor_prover = RoundProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = floor_prover.prove(&mut prover_trans, &params, &instance);
    println!("round proving time: {:?} ms", start.elapsed().as_millis());

    let proof_bytes = proof.to_bytes().unwrap();
    println!("round proof size: {:?} byts", proof_bytes.len());

    // Verifier.
    let floor_verifier = RoundVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = RoundProof::from_bytes(&proof_bytes).unwrap();

    let start = Instant::now();
    let res = floor_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);
    println!("round verifying time: {:?} ms", start.elapsed().as_millis());

    assert!(res);
}

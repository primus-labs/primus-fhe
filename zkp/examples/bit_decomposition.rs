use algebra::derive::{DecomposableField, Field};
use algebra::utils::Transcript;
use algebra::AsFrom;
use algebra::{BabyBear, BabyBearExetension, Basis, DenseMultilinearExtension};
use algebra::{DecomposableField, Field, FieldUniformSampler};
use itertools::izip;
use pcs::multilinear::BrakedownPCS;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use zkp::piop::bit_decomposition::{
    BitDecompositionParams, BitDecompositionProof, BitDecompositionProver, BitDecompositionVerifier,
};
use zkp::piop::BitDecompositionInstance;

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE s.t. N = 2^num_vars
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = BabyBear: denotes the ciphertext modulus in RLWE
const LOG_DIM_RLWE: usize = 10;
const LOG_B: u32 = 1;

fn generate_instance<Fq: Field + DecomposableField, F: DecomposableField>(
    num_instances: usize,
    num_vars: usize,
    base_len: usize,
    base: F,
    bits_len: usize,
) -> BitDecompositionInstance<F> {
    let mut rng = thread_rng();
    // sample d in the range of Fq
    let uniform = <FieldUniformSampler<Fq>>::new();
    let d = (0..num_instances)
        .map(|_| {
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                (0..(1 << num_vars))
                    .map(|_| {
                        F::new(F::Value::as_from(
                            uniform.sample(&mut rng).value().into() as u64 as f64,
                        ))
                    })
                    .collect(),
            ))
        })
        .collect::<Vec<_>>();

    let d_bits: Vec<_> = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut decomposed_bits = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    for (val, bits) in izip!(&d, &d_bits) {
        decomposed_bits.add_decomposed_bits_instance(val, bits);
    }
    decomposed_bits
}

#[derive(Field, DecomposableField)]
#[modulus = 1024]
pub struct Fq(u32);

fn main() {
    // let base_len = LOG_B as usize;
    // let base: FF = FF::new(1 << base_len);
    // let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    // let num_vars = LOG_DIM_RLWE;

    // Generate 2 * n = 2048 instances to be proved, each instance consisting of N = 2^num_vars values to be decomposed.
    // let decomposed_bits = generate_instance::<FF>(2 * DIM_LWE, num_vars, base_len, base, bits_len);

    let base_len = LOG_B as usize;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<Fq>>::new(base_len as u32).decompose_len();
    let num_vars = LOG_DIM_RLWE;

    let instance = generate_instance::<Fq, FF>(2, num_vars, base_len, base, bits_len);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = instance.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = BitDecompositionParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    params.setup(&instance.info(), code_spec);

    // Prover.
    let bd_prover = BitDecompositionProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = bd_prover.prove(&mut prover_trans, &params, &instance);
    println!(
        "bit decomposition proving time: {:?} ms",
        start.elapsed().as_millis()
    );

    let proof_bytes = proof.to_bytes().unwrap();
    println!(
        "bit decomposition proof size: {:?} bytes",
        proof_bytes.len()
    );

    // Verifier.
    let bd_verifier = BitDecompositionVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = BitDecompositionProof::from_bytes(&proof_bytes).unwrap();
    let start = Instant::now();
    let res = bd_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);
    println!(
        "bit decomposition verifying time: {:?} ms",
        start.elapsed().as_millis()
    );
    assert!(res);
}

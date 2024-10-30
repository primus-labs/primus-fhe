use algebra::derive::{DecomposableField, Field};
use algebra::utils::Transcript;
use algebra::{BabyBear, BabyBearExetension, DenseMultilinearExtension, SparsePolynomial};
use algebra::{Field, FieldUniformSampler};
use num_traits::{One, Zero};
use pcs::multilinear::BrakedownPCS;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use zkp::piop::lift::{LiftParams, LiftProof, LiftProver, LiftVerifier};
use zkp::piop::{BitDecompositionInstanceInfo, LiftInstance};

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
const LOG_B: usize = 2;

#[derive(Field, DecomposableField)]
#[modulus = 1024]
pub struct Fq(u32);

fn transform(
    num_vars: usize,
    input: FF,
    q: FF,
    dim_rlwe: FF,
) -> (DenseMultilinearExtension<FF>, SparsePolynomial<FF>) {
    let factor = (FF::one() + FF::one()) * dim_rlwe / q;
    let mapped_input = factor * input;
    let mut output = vec![FF::zero(); 1 << num_vars];
    let mut sparse_output = SparsePolynomial::new(num_vars);
    if mapped_input < dim_rlwe {
        let idx = mapped_input.value() as usize;
        output[idx] = FF::one();
        sparse_output.add_eval(idx, FF::one());
    } else {
        let idx = (mapped_input - dim_rlwe).value() as usize;
        output[idx] = -FF::one();
        sparse_output.add_eval(idx, -FF::one());
    }
    (
        DenseMultilinearExtension::from_evaluations_vec(num_vars, output),
        sparse_output,
    )
}

fn main() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<Fq>>::new();

    let base_len = LOG_B;
    let base: FF = FF::new(1 << base_len);
    let num_vars = LOG_DIM_RLWE;
    let q = FF::new(Fq::MODULUS_VALUE);
    let dim_rlwe = FF::new(1 << num_vars);

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| FF::new(uniform.sample(&mut rng).value()))
            .collect(),
    ));
    let mut outputs = Vec::with_capacity(1 << num_vars);
    let mut sparse_outputs = Vec::with_capacity(1 << num_vars);
    for x in input.iter() {
        let (output, sparse_output) = transform(num_vars, *x, q, dim_rlwe);
        outputs.push(Rc::new(output));
        sparse_outputs.push(Rc::new(sparse_output));
    }

    let bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: num_vars,
        num_vars,
        num_instances: 0,
    };

    let instance = LiftInstance::new(
        num_vars,
        q,
        dim_rlwe,
        &input,
        &outputs,
        &sparse_outputs,
        &bits_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = instance.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = LiftParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();

    let start = Instant::now();
    params.setup(&instance.info(), code_spec);
    println!("lift setup time: {:?} ms", start.elapsed().as_millis());

    // Prover.
    let floor_prover = LiftProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = floor_prover.prove(&mut prover_trans, &params, &instance);
    println!("lift proving time: {:?} ms", start.elapsed().as_millis());

    let proof_bytes = proof.to_bytes().unwrap();
    println!("lift proof size: {:?} bytes", proof_bytes.len());

    // Verifier.
    let floor_verifier = LiftVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = LiftProof::from_bytes(&proof_bytes).unwrap();

    let start = Instant::now();
    let res = floor_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);
    println!("lift verifying time: {:?} ms", start.elapsed().as_millis());

    assert!(res);
}

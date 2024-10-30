use std::{rc::Rc, time::Instant};

use algebra::{utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, Field};
use pcs::{
    multilinear::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand::{thread_rng, Rng};
use sha2::Sha256;
use zkp::piop::{
    AdditionInZqInstance, AdditionInZqParams, AdditionInZqProof, AdditionInZqProver,
    AdditionInZqVerifier, BitDecompositionInstanceInfo,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn main() {
    let mut rng = thread_rng();
    let bits_len = 10;
    let modulus = 1024;
    let q = FF::new(modulus);
    let base_len = 2;
    let base = FF::new(1 << base_len);
    let num_vars = 10;

    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| rng.gen_range(0..modulus))
        .collect();

    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| rng.gen_range(0..modulus))
        .collect();

    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x + y >= modulus {
                ((x + y) % modulus, 1)
            } else {
                ((x + y) % modulus, 0)
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            a.iter().map(|&x| FF::new(x)).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            b.iter().map(|&x| FF::new(x)).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            c.iter().map(|&x| FF::new(x)).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        k.iter().map(|&x| FF::new(x)).collect(),
    ));

    let bits_info = BitDecompositionInstanceInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };

    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = instance.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = AdditionInZqParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let start = Instant::now();
    params.setup(&instance.info(), code_spec);
    println!(
        "addition in zq setup time: {:?} ms",
        start.elapsed().as_millis()
    );

    // Prover.
    let bd_prover = AdditionInZqProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = bd_prover.prove(&mut prover_trans, &params, &instance);
    println!(
        "addition in zq proving time: {:?} ms",
        start.elapsed().as_millis()
    );

    let proof_bytes = proof.to_bytes().unwrap();
    println!("addition in zq proof size: {:?} byts", proof_bytes.len());

    // Verifier.
    let bd_verifier = AdditionInZqVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();
    let proof = AdditionInZqProof::from_bytes(&proof_bytes).unwrap();

    let start = Instant::now();
    let res = bd_verifier.verify(&mut verifier_trans, &params, &info, &proof);
    println!(
        "addition in zq verifying time: {:?} ms",
        start.elapsed().as_millis()
    );
    assert!(res);
}

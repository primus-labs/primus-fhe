use std::time::Instant;

use algebra::{utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, Field};
use num_traits::Zero;
use pcs::{
    multilinear::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand::prelude::*;
use sha2::Sha256;
use zkp::piop::{
    lookup::{LookupParams, LookupProof, LookupProver, LookupVerifier},
    LookupInstance,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn main() {
    let num_vars = 10;
    let block_size = 2;
    let lookup_num = 2;
    let range = 1024;

    let mut rng = thread_rng();
    let f_vec: Vec<DenseMultilinearExtension<FF>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            DenseMultilinearExtension::from_evaluations_vec(num_vars, f_evaluations)
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = DenseMultilinearExtension::from_evaluations_vec(num_vars, t_evaluations);

    let instance = LookupInstance::from_slice(&f_vec, t, block_size);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = instance.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = LookupParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();

    let start = Instant::now();
    params.setup(&instance.info(), code_spec);
    println!("lookup setup time: {:?} ms", start.elapsed().as_millis());

    // Prover.
    let lookup_prover = LookupProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = lookup_prover.prove(&mut prover_trans, &params, &instance);
    println!("lookup proving time: {:?} ms", start.elapsed().as_millis());

    let proof_bytes = proof.to_bytes().unwrap();
    println!("lookup proof size: {:?} bytes", proof_bytes.len());
    // Verifier.
    let lookup_verifier = LookupVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = LookupProof::from_bytes(&proof_bytes).unwrap();
    let start = Instant::now();
    let res = lookup_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);
    println!(
        "lookup verifying time: {:?} ms",
        start.elapsed().as_millis()
    );
    assert!(res);
}

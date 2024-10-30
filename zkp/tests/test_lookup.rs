use algebra::{
    derive::{DecomposableField, Field, Prime},
    utils::Transcript,
    BabyBear, BabyBearExetension, DenseMultilinearExtension, Field,
};
use num_traits::Zero;
use pcs::{
    multilinear::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand::prelude::*;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{
    lookup::{LookupParams, LookupProof, LookupProver, LookupVerifier},
    LookupIOP, LookupInstance,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_trivial_range_check() {
    // prepare parameters

    let num_vars = 4;
    let block_size = 2;
    let range: usize = 6;

    // construct a trivial example

    let f0 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 4, 5, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 0),
    ));
    let f1 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 2, 5, 3, 4, 0, 1, 4, 3, 2, 1, 0, 4, 1, 1, 3),
    ));
    let f2 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 1, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 1),
    ));
    let f3 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 5, 2, 4, 0, 1, 2, 3, 2, 1, 0, 3, 1, 1, 1),
    ));
    let f4 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 1, 5, 2, 4, 0, 1, 3, 3, 2, 1, 0, 5, 1, 1, 2),
    ));

    let f_vec = [f0, f1, f2, f3, f4];

    let mut t_evaluations: Vec<_> = (0..range).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    // construct instance

    let mut instance = LookupInstance::<FF>::from_slice(
        &f_vec.iter().map(|d| d.as_ref().clone()).collect::<Vec<_>>(),
        t.as_ref().clone(),
        block_size,
    );
    let info = instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut lookup = LookupIOP::default();

    lookup.prover_generate_first_randomness(&mut prover_trans, &mut instance);
    lookup.generate_second_randomness(&mut prover_trans, &info);
    lookup.generate_randomness_for_eq_function(&mut prover_trans, &info);
    let kit = lookup.prove(&mut prover_trans, &instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut lookup = LookupIOP::default();

    lookup.verifier_generate_first_randomness(&mut verifier_trans);
    lookup.generate_second_randomness(&mut verifier_trans, &info);
    lookup.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = lookup.verify(&mut verifier_trans, &wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_random_range_check() {
    // prepare parameters

    let num_vars = 8;
    let block_size = 4;
    let block_num = 5;
    let residual_size = 1;
    let lookup_num = block_num * block_size + residual_size;
    let range = 59;

    let mut rng = thread_rng();
    let f_vec: Vec<Rc<DenseMultilinearExtension<FF>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                f_evaluations,
            ))
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    let mut instance = LookupInstance::from_slice(
        &f_vec.iter().map(|d| d.as_ref().clone()).collect::<Vec<_>>(),
        t.as_ref().clone(),
        block_size,
    );
    let info = instance.info();
    let mut lookup = LookupIOP::default();

    let mut prover_trans = Transcript::<FF>::new();
    lookup.prover_generate_first_randomness(&mut prover_trans, &mut instance);
    lookup.generate_second_randomness(&mut prover_trans, &info);
    lookup.generate_randomness_for_eq_function(&mut prover_trans, &info);
    let kit = lookup.prove(&mut prover_trans, &instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut lookup = LookupIOP::default();
    lookup.verifier_generate_first_randomness(&mut verifier_trans);
    lookup.generate_second_randomness(&mut verifier_trans, &info);
    lookup.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = lookup.verify(&mut verifier_trans, &wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_lookup_snark() {
    // prepare parameters
    let num_vars = 8;
    let block_size = 4;
    let block_num = 5;
    let residual_size = 1;
    let lookup_num = block_num * block_size + residual_size;
    let range = 59;

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

    // Parameters.
    let mut params = LookupParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    params.setup(&instance.info(), code_spec);

    // Prover.
    let lookup_prover = LookupProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let proof = lookup_prover.prove(&mut prover_trans, &params, &instance);

    let proof_bytes = proof.to_bytes().unwrap();

    // Verifier.
    let lookup_verifier = LookupVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = LookupProof::from_bytes(&proof_bytes).unwrap();
    let res = lookup_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);

    assert!(res);
}

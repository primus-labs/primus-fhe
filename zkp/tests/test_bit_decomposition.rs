use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, Basis, DenseMultilinearExtension, Field,
    FieldUniformSampler,
};
use itertools::izip;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use zkp::piop::bit_decomposition::{
    BitDecompositionIOP, BitDecompositionInstance, BitDecompositionParams, BitDecompositionProof,
    BitDecompositionProver, BitDecompositionVerifier,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_single_trivial_bit_decomposition_base_2() {
    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len = 2;
    let num_vars = 2;

    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 1, 2, 3),
    ));
    let d_bits = vec![
        // 0th bit
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 0, 1),
        )),
        // 1st bit
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 1, 1),
        )),
    ];

    let mut prover_key = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    prover_key.add_decomposed_bits_instance(&d, &d_bits);
    let info = prover_key.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut prover_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = bd_iop.prove(&mut prover_trans, &prover_key);

    let evals = prover_key.evaluate(&kit.randomness);

    let wrapper: zkp::sumcheck::ProofWrapper<BabyBear> = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut verifier_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = bd_iop.verify(&mut verifier_trans, &wrapper, &evals, &prover_key.info());

    assert!(check);
}

#[test]
fn test_batch_trivial_bit_decomposition_base_2() {
    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len = 2;
    let num_vars = 2;

    let d = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 2, 3),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 2, 3),
        )),
    ];
    let d_bits = vec![
        vec![
            // 0th bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 1, 0, 1),
            )),
            // 1st bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 0, 1, 1),
            )),
        ],
        vec![
            // 0th bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 1, 0, 1),
            )),
            // 1st bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 0, 1, 1),
            )),
        ],
    ];

    let mut instance = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    for (d_val, d_bits) in izip!(d, d_bits) {
        instance.add_decomposed_bits_instance(&d_val, &d_bits);
    }

    let info = instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut prover_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = bd_iop.prove(&mut prover_trans, &instance);

    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut verifier_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = bd_iop.verify(&mut verifier_trans, &wrapper, &evals, &instance.info());

    assert!(check);
}

#[test]
fn test_single_bit_decomposition() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);

    let info = instance.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut prover_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = bd_iop.prove(&mut prover_trans, &instance);

    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut verifier_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = bd_iop.verify(&mut verifier_trans, &wrapper, &evals, &instance.info());

    assert!(check);
}

#[test]
fn test_batch_bit_decomposition() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
    ];

    let d_bits: Vec<_> = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut instance = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    for (val, bits) in izip!(d, d_bits) {
        instance.add_decomposed_bits_instance(&val, &bits);
    }

    let info = instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut prover_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = bd_iop.prove(&mut prover_trans, &instance);

    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut verifier_trans = Transcript::<FF>::new();

    let mut bd_iop = BitDecompositionIOP::default();

    bd_iop.generate_randomness(&mut verifier_trans, &info);
    bd_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = bd_iop.verify(&mut verifier_trans, &wrapper, &evals, &instance.info());

    assert!(check);
}

#[test]
fn test_bit_decomposition_snark() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = BitDecompositionInstance::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

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

    let proof = bd_prover.prove(&mut prover_trans, &params, &instance);

    let proof_bytes = proof.to_bytes().unwrap();

    // Verifier.
    let bd_verifier = BitDecompositionVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = BitDecompositionProof::from_bytes(&proof_bytes).unwrap();

    let res = bd_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);

    assert!(res);
}

use algebra::{
    utils::Transcript, BabyBear, BabyBearExetension, DenseMultilinearExtension, Field,
    FieldUniformSampler,
};
use pcs::{
    multilinear::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{
    floor::{FloorParams, FloorProof, FloorProver, FloorVerifier},
    BitDecompositionInstanceInfo, FloorIOP, FloorInstance,
};

type FF = BabyBear; // field type
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;
const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
const FT: u32 = 1024; // message space
const LOG_FT: usize = FT.next_power_of_two().ilog2() as usize;
const FK: u32 = (FP - 1) / FT;
const LOG_FK: u32 = FK.next_power_of_two().ilog2();
const DELTA: u32 = (1 << LOG_FK) - FK;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[inline]
fn decode(c: FF) -> u32 {
    (c.value() as f64 * FT as f64 / FP as f64).floor() as u32 % FT
}

#[test]
fn test_floor() {
    let decode_4 = |c: FF| (c.value() as f64 * 4_f64 / FP as f64).floor() as u32 % FT;
    assert_eq!(decode_4(FF::new(0)), 0);
    assert_eq!(decode_4(FF::new(FP / 4)), 0);
    assert_eq!(decode_4(FF::new(FP / 4 + 1)), 1);
    assert_eq!(decode_4(FF::new(FP / 2)), 1);
    assert_eq!(decode_4(FF::new(FP / 2 + 1)), 2);
}

#[test]
fn test_floor_naive_iop() {
    const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
    const FT: u32 = 4; // message space
    const LOG_FT: usize = FT.next_power_of_two().ilog2() as usize;
    const FK: u32 = (FP - 1) / FT;
    const LOG_FK: u32 = FK.next_power_of_two().ilog2();
    const DELTA: u32 = (1 << LOG_FK) - FK;

    let k = FF::new(FK);
    let k_bits_len = LOG_FK as usize;
    let delta: FF = FF::new(DELTA);

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 2;

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, FP/4, FP/4 + 1, FP/2 + 1),
    ));
    let output = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 0, 1, 2),
    ));
    let output_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 1,
    };

    let offset_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <FloorInstance<FF>>::new(
        num_vars,
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let info = instance.info();
    let mut floor_iop = FloorIOP::default();
    let mut prover_trans = Transcript::<FF>::new();
    floor_iop.generate_randomness(&mut prover_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = floor_iop.prove(&mut prover_trans, &instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();

    let mut floor_iop = FloorIOP::default();
    let mut verifier_trans = Transcript::<FF>::new();
    floor_iop.generate_randomness(&mut verifier_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = floor_iop.verify(&mut verifier_trans, &wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_floor_random_iop() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    let k = FF::new(FK);
    let k_bits_len = LOG_FK as usize;
    let delta: FF = FF::new(DELTA);

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 10;

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
        num_instances: 1,
    };

    let offset_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <FloorInstance<FF>>::new(
        num_vars,
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let info = instance.info();
    let mut floor_iop = FloorIOP::default();
    let mut prover_trans = Transcript::<FF>::new();
    floor_iop.generate_randomness(&mut prover_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = floor_iop.prove(&mut prover_trans, &instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let mut floor_iop = FloorIOP::default();
    let mut verifier_trans = Transcript::<FF>::new();
    floor_iop.generate_randomness(&mut verifier_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = floor_iop.verify(&mut verifier_trans, &wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_floor_random_iop_extension_field() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    let k = FF::new(FK);
    let k_bits_len = LOG_FK as usize;
    let delta: FF = FF::new(DELTA);

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 10;

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
        num_instances: 1,
    };

    let offset_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <FloorInstance<FF>>::new(
        num_vars,
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let instance_ef = instance.to_ef::<EF>();
    let info = instance_ef.info();
    let mut floor_iop = FloorIOP::default();
    let mut prover_trans = Transcript::<EF>::new();

    floor_iop.generate_randomness(&mut prover_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = floor_iop.prove(&mut prover_trans, &instance_ef);
    let evals = instance.evaluate_ext(&kit.randomness);

    let wrapper = kit.extract();

    let mut floor_iop = FloorIOP::default();
    let mut verifier_trans = Transcript::<EF>::new();

    floor_iop.generate_randomness(&mut verifier_trans, &info);
    floor_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = floor_iop.verify(&mut verifier_trans, &wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_floor_snark() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    let k = FF::new(FK);
    let delta: FF = FF::new(DELTA);

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 10;

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
        num_instances: 1,
    };

    let offset_bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: LOG_FK as usize,
        num_vars,
        num_instances: 2,
    };

    let instance = <FloorInstance<FF>>::new(
        num_vars,
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    // Parameters.
    let mut params = FloorParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    params.setup(&instance.info(), code_spec);

    // Prover.
    let floor_prover = FloorProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let proof = floor_prover.prove(&mut prover_trans, &params, &instance);

    let proof_bytes = proof.to_bytes().unwrap();

    // Verifier.
    let floor_verifier = FloorVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = FloorProof::from_bytes(&proof_bytes).unwrap();

    let res = floor_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);

    assert!(res);
}

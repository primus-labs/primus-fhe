use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    BabyBear, BabyBearExetension, DecomposableField, DenseMultilinearExtension, Field,
    FieldUniformSampler,
};
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{round::RoundSnarks, DecomposedBitsInfo, RoundIOP, RoundInstance};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};

type FF = BabyBear; // field type
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;
const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
const FT: u32 = 4; // message space
const LOG_FT: u32 = FT.next_power_of_two().ilog2();
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
fn test_round() {
    assert_eq!(decode(FF::new(0)), 0);
    assert_eq!(decode(FF::new(FP / 4)), 0);
    assert_eq!(decode(FF::new(FP / 4 + 1)), 1);
    assert_eq!(decode(FF::new(FP / 2)), 1);
    assert_eq!(decode(FF::new(FP / 2 + 1)), 2);
}

#[test]
fn test_round_naive_iop() {
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
    let output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: 2,
        num_vars,
        num_instances: 1,
    };

    let offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let info = instance.info();

    let kit = RoundIOP::<FF>::prove(&instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = RoundIOP::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_round_random_iop() {
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
    let output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: 2,
        num_vars,
        num_instances: 1,
    };

    let offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let info = instance.info();

    let kit = RoundIOP::<FF>::prove(&instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = RoundIOP::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_round_random_iop_extension_field() {
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
    let output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: 2,
        num_vars,
        num_instances: 1,
    };

    let offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let instance_ef = instance.to_ef::<EF>();
    let info = instance_ef.info();

    let kit = RoundIOP::<EF>::prove(&instance_ef);
    let evals = instance.evaluate_ext(&kit.randomness);

    let wrapper = kit.extract();
    let check = RoundIOP::<EF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_snarks()
{
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
    let output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FT as usize,
        num_vars,
        num_instances: 1,
    };

    let offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FK as usize,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        k,
        delta,
        input,
        output,
        &output_bits_info,
        &offset_bits_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <RoundSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}
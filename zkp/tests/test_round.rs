use algebra::{
    BabyBear, BabyBearExetension, DecomposableField, DenseMultilinearExtension, Field,
    FieldUniformSampler,
};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{DecomposedBitsInfo, FloorIOP, FloorInstance, RoundIOP, RoundInstance, RoundSnarks};

// type FF = BabyBear; // field type
// type EF = BabyBearExetension;
type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;
const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
const FT: u32 = 1024; // message space
const LOG_FT: usize = FT.next_power_of_two().ilog2() as usize;
const FK: u32 = (FP - 1) / (2 * FT);
const LOG_2FK: u32 = (2 * FK).next_power_of_two().ilog2();
const DELTA: u32 = (1 << LOG_2FK) - (2 * FK);

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
    (c.value() as f64 * FT as f64 / FP as f64).round() as u32 % FT
}

#[test]
fn test_round() {
    let decode_4 = |c: FF| (c.value() as f64 * 4 as f64 / FP as f64).round() as u32 % FT;
    assert_eq!(decode_4(FF::new(0)), 0);
    assert_eq!(decode_4(FF::new(FP / 4)), 1);
    assert_eq!(decode_4(FF::new(FP / 4 + 1)), 1);
    assert_eq!(decode_4(FF::new(FP / 2)), 2);
    assert_eq!(decode_4(FF::new(FP / 2 + 1)), 2);
}

#[test]
fn test_round_naive_iop() {
    const FP: u32 = FF::MODULUS_VALUE; // ciphertext space
    const FT: u32 = 4; // message space
    const LOG_FT: usize = FT.next_power_of_two().ilog2() as usize;
    const FK: u32 = (FP - 1) / (2 * FT);
    const LOG_2FK: u32 = (2 * FK).next_power_of_two().ilog2();
    const DELTA: u32 = (1 << LOG_2FK) - (2 * FK);

    let q = FF::new(FT);
    let k = FF::new(FK);
    let k_bits_len = LOG_2FK as usize;
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
        field_vec!(FF; 0, 1, 1, 2),
    ));
    let mut output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 0,
    };

    let mut offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 0,
    };

    let instance = <RoundInstance<FF>>::new(
        num_vars,
        q,
        k,
        delta,
        input,
        output,
        &mut output_bits_info,
        &mut offset_bits_info,
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

    let q = FF::new(FT);
    let k = FF::new(FK);
    let k_bits_len = LOG_2FK as usize;
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
    let mut output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 0,
    };

    let mut offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 0,
    };

    let instance = <RoundInstance<FF>>::new(
        num_vars,
        q,
        k,
        delta,
        input,
        output,
        &mut output_bits_info,
        &mut offset_bits_info,
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

    let q = FF::new(FT);
    let k = FF::new(FK);
    let k_bits_len = LOG_2FK as usize;
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
    let mut output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 0,
    };

    let mut offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        num_vars,
        q,
        k,
        delta,
        input,
        output,
        &mut output_bits_info,
        &mut offset_bits_info,
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
fn test_snarks() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    let q = FF::new(FT);
    let k = FF::new(FK);
    let k_bits_len = LOG_2FK as usize;
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
    let mut output_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: LOG_FT,
        num_vars,
        num_instances: 0,
    };

    let mut offset_bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len: k_bits_len,
        num_vars,
        num_instances: 2,
    };

    let instance = <RoundInstance<FF>>::new(
        num_vars,
        q,
        k,
        delta,
        input,
        output,
        &mut output_bits_info,
        &mut offset_bits_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <RoundSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}

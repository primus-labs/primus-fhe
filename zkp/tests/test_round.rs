use algebra::{
    derive::{Field, Prime, NTT},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{DecomposedBitsInfo, RoundIOP, RoundInstance};

#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

type FF = Fp32; // field type
const FP: u32 = 132120577; // ciphertext space
const FT: u32 = 4; // message space
const FK: u32 = (FP - 1) / FT;

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
    (c.get() as f64 * FT as f64 / FP as f64).floor() as u32 % FT
}

#[test]
fn test_round() {
    assert_eq!(decode(FF::new(1)), 0);
    assert_eq!(decode(FF::new(FP / 4)), 0);
    assert_eq!(decode(FF::new(FP / 4 + 1)), 1);
    assert_eq!(decode(FF::new(FP / 2)), 1);
    assert_eq!(decode(FF::new(FP / 2 + 1)), 2);
}

#[test]
fn test_round_naive_iop() {
    // k = (132120577 - 1) / FT = 33030144 = 2^25 - 2^19
    let k = FF::new(FK);
    let k_bits_len: u32 = 25;
    let delta: FF = FF::new(1 << 19);

    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 2;

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, FP/4, FP/4 + 1, FP/2 + 1),
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

    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let lambda_1 = uniform.sample(&mut rng);
    let lambda_2 = uniform.sample(&mut rng);

    let proof = RoundIOP::prove(&instance, &u, (lambda_1, lambda_2));
    let subclaim = RoundIOP::verify(&proof, &instance.info());

    assert!(subclaim.verify_subclaim(
        &u,
        (lambda_1, lambda_2),
        &instance.input,
        &instance.output,
        &instance.output_bits.instances[0],
        &instance.offset,
        &instance.offset_aux_bits.instances[0],
        &instance.offset_aux_bits.instances[1],
        &instance.option,
        &info
    ))
}

#[test]
fn test_round_random_iop() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    // k = (132120577 - 1) / FT = 33030144 = 2^25 - 2^19
    let k = FF::new(FK);
    let k_bits_len: u32 = 25;
    let delta: FF = FF::new(1 << 19);

    let base_len: u32 = 1;
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

    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let lambda_1 = uniform.sample(&mut rng);
    let lambda_2 = uniform.sample(&mut rng);

    let proof = RoundIOP::prove(&instance, &u, (lambda_1, lambda_2));
    let subclaim = RoundIOP::verify(&proof, &instance.info());

    assert!(subclaim.verify_subclaim(
        &u,
        (lambda_1, lambda_2),
        &instance.input,
        &instance.output,
        &instance.output_bits.instances[0],
        &instance.offset,
        &instance.offset_aux_bits.instances[0],
        &instance.offset_aux_bits.instances[1],
        &instance.option,
        &info
    ))
}

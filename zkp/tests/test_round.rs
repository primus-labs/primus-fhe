use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    utils::Transcript,
    BabyBear, BabyBearExetension, DecomposableField, DenseMultilinearExtensionBase, Field,
    FieldUniformSampler,
};
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{DecomposedBitsInfo, RoundIOP, RoundInstance};

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 2013265921]
pub struct Fp32(u64);

// field type
type FF = BabyBear;
type EF = BabyBearExetension;
const FP: u32 = 2013265921; // ciphertext space
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
    // delta = (1 << k_bits_len) - FK
    let k = FF::new(FK);
    let k_bits_len: u32 = 31;
    let delta: FF = FF::new((1 << k_bits_len) - FK);

    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 2;

    let input = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, FP/4, FP/4 + 1, FP/2 + 1),
    ));
    let output = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
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

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let p_lambda: Vec<EF> =
        prover_trans.get_vec_ext_field_challenge(b"random point to randomize sumcheck protocol", 2);
    let v_lambda: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to randomize sumcheck protocol", 2);
    assert_eq!(p_lambda, v_lambda);

    let proof = <RoundIOP<FF, EF>>::prove(
        &mut prover_trans,
        &instance,
        &prover_u,
        (p_lambda[0], p_lambda[1]),
    );
    let subclaim = <RoundIOP<FF, EF>>::verify(&mut verifier_trans, &proof, &instance.info());

    assert!(subclaim.verify_subclaim(
        &verifier_u,
        (v_lambda[0], v_lambda[1]),
        &instance.input,
        &instance.output,
        &instance.output_bits.d_bits[0],
        &instance.offset,
        &instance.offset_aux_bits.d_bits[0],
        &instance.offset_aux_bits.d_bits[1],
        &instance.option,
        &info
    ))
}

#[test]
fn test_round_random_iop() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    // delta = (1 << k_bits_len) - FK
    let k = FF::new(FK);
    let k_bits_len: u32 = 31;
    let delta: FF = FF::new((1 << k_bits_len) - FK);

    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 10;

    let input = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));
    let output = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
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

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let p_lambda: Vec<EF> =
        prover_trans.get_vec_ext_field_challenge(b"random point to randomize sumcheck protocol", 2);
    let v_lambda: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to randomize sumcheck protocol", 2);

    let proof = <RoundIOP<FF, EF>>::prove(
        &mut prover_trans,
        &instance,
        &prover_u,
        (p_lambda[0], p_lambda[1]),
    );
    let subclaim = <RoundIOP<FF, EF>>::verify(&mut verifier_trans, &proof, &instance.info());

    assert!(subclaim.verify_subclaim(
        &verifier_u,
        (v_lambda[0], v_lambda[1]),
        &instance.input,
        &instance.output,
        &instance.output_bits.d_bits[0],
        &instance.offset,
        &instance.offset_aux_bits.d_bits[0],
        &instance.offset_aux_bits.d_bits[1],
        &instance.option,
        &info
    ))
}

use algebra::{
    derive::{DecomposableField, Field, Prime},
    utils::Transcript,
    BabyBear, BabyBearExetension, Basis, DecomposableField, DenseMultilinearExtensionBase, Field,
    FieldUniformSampler,
};
use num_traits::{One, Zero};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{AdditionInZq, AdditionInZqInstance};

#[derive(Field, DecomposableField, Prime)]
#[modulus = 2013265921]
pub struct Fp32(u64);

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

// field type
type FF = BabyBear;
type EF = BabyBearExetension;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_trivial_addition_in_zq() {
    let q = FF::new(9);
    let base_len: u32 = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len: u32 = 4;
    let abc = vec![
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 4, 6, 8, 2),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 7, 3, 0, 1),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 2, 0, 8, 3),
        )),
    ];
    let k = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 1, 0, 0),
    ));

    // decompose bits of every element in a, b, c
    let abc_bits: Vec<_> = abc
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();
    let abd_bits_ref: Vec<_> = abc_bits.iter().collect();

    let abc_instance = AdditionInZqInstance::from_slice(&abc, &k, q, base, base_len, bits_len);
    let addition_info = abc_instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = <AdditionInZq<FF, EF>>::prove(&mut prover_trans, &abc_instance, &prover_u);
    let subclaim = <AdditionInZq<FF, EF>>::verify(
        &mut verifier_trans,
        &proof,
        &addition_info.decomposed_bits_info,
    );
    assert!(subclaim.verify_subclaim(
        q,
        &abc,
        k.as_ref(),
        &abd_bits_ref,
        &verifier_u,
        &addition_info
    ));
}

#[test]
fn test_random_addition_in_zq() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let base_len: u32 = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

    // Addition in Zq
    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.value() + y.value() >= Fq::MODULUS_VALUE {
                (*x + *y, Fq::one())
            } else {
                (*x + *y, Fq::zero())
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            // Convert to Fp
            a.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            b.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            c.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        k.iter().map(|x: &Fq| FF::new(x.value())).collect(),
    ));

    // decompose bits of every element in a, b, c
    let abc_bits: Vec<_> = abc
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();
    let abc_bits_ref: Vec<_> = abc_bits.iter().collect();

    let abc_instance = AdditionInZqInstance::from_slice(&abc, &k, q, base, base_len, bits_len);
    let addition_info = abc_instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = <AdditionInZq<FF, EF>>::prove(&mut prover_trans, &abc_instance, &prover_u);
    let subclaim = AdditionInZq::verify(
        &mut verifier_trans,
        &proof,
        &addition_info.decomposed_bits_info,
    );
    assert!(subclaim.verify_subclaim(
        q,
        &abc,
        k.as_ref(),
        &abc_bits_ref,
        &verifier_u,
        &addition_info
    ));
}

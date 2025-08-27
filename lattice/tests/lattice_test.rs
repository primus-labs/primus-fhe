use std::sync::LazyLock;

use algebra::decompose::NonPowOf2ApproxSignedBasis;
use algebra::modulus::PowOf2Modulus;
use algebra::ntt::NumberTheoryTransform;
use algebra::polynomial::FieldPolynomial;
use algebra::random::DiscreteGaussian;
use algebra::reduce::{ReduceAdd, ReduceMulAdd, ReduceSub};
use algebra::{Field, NttField, U32FieldEval};
use lattice::{GadgetRlwe, Lwe, NttRlwe, Rlwe};
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rand::{thread_rng, Rng};

type Inner = u32; // inner type
type FF = U32FieldEval<132120577>; // field type
type PolyFF = FieldPolynomial<FF>;

const RR: Inner = 1024;

const LOG_N: u32 = 5;
const N: usize = 1 << LOG_N; // length
const BASE_BITS: u32 = 3;

const FP: Inner = <FF as Field>::MODULUS_VALUE; // ciphertext space
const FT: Inner = 4; // message space

static NTT_TABLE: LazyLock<<FF as NttField>::Table> =
    LazyLock::new(|| FF::generate_ntt_table(LOG_N).unwrap());

#[test]
fn test_lwe() {
    let rng = &mut rand::thread_rng();

    let dis = Uniform::new(0u32, RR);
    let modulus = <PowOf2Modulus<u32>>::new(RR);

    let a1 = rng.sample_iter(dis).take(N).collect::<Vec<Inner>>();
    let a2 = rng.sample_iter(dis).take(N).collect::<Vec<Inner>>();
    let a3 = a1
        .iter()
        .zip(a2.iter())
        .map(|(&u, &v)| modulus.reduce_add(u, v))
        .collect::<Vec<Inner>>();

    let b1: Inner = rng.sample(dis);
    let b2: Inner = rng.sample(dis);
    let b3: Inner = modulus.reduce_add(b1, b2);

    let lwe1 = Lwe::new(a1, b1);
    let lwe2 = Lwe::new(a2, b2);
    let lwe3 = Lwe::new(a3, b3);
    assert_eq!(lwe1.clone().add_reduce_component_wise(&lwe2, modulus), lwe3);
    assert_eq!(lwe3.sub_reduce_component_wise(&lwe2, modulus), lwe1);
}

#[test]
fn test_lwe_he() {
    const RP: Inner = RR;
    const RT: Inner = 4;
    const EMAX: Inner = RR / 16;

    #[inline]
    fn encode(m: Inner) -> Inner {
        (m as f64 * RP as f64 / RT as f64).round() as Inner
    }

    #[inline]
    fn decode(c: Inner) -> Inner {
        (c as f64 * RT as f64 / RP as f64).round() as Inner % RT
    }

    let mut rng = thread_rng();

    let dis = Uniform::new(0u32, RR);
    let modulus = <PowOf2Modulus<u32>>::new(RR);

    let v0: Inner = rng.gen_range(0..RT);
    let v1: Inner = rng.gen_range(0..RT);

    let s = (&mut rng).sample_iter(dis).take(N).collect::<Vec<Inner>>();

    let mut encrypt = |v| {
        let a = (&mut rng).sample_iter(dis).take(N).collect::<Vec<Inner>>();
        let b = a
            .iter()
            .zip(&s)
            .fold(0, |acc, (&x, &y)| modulus.reduce_mul_add(x, y, acc));
        let b = modulus.reduce_add(b, encode(v));
        let b = modulus.reduce_add(b, rng.gen_range(0..EMAX));

        Lwe::new(a, b)
    };

    let lwe1 = encrypt(v0);

    let lwe2 = encrypt(v1);

    let ret = lwe1.add_reduce_component_wise(&lwe2, modulus);

    let a_mul_s = ret
        .a()
        .iter()
        .zip(&s)
        .fold(0, |acc, (&x, &y)| modulus.reduce_mul_add(x, y, acc));
    let decrypted = decode(modulus.reduce_sub(ret.b(), a_mul_s));
    assert_eq!(decrypted, (v0 + v1) % RT);
}

#[test]
fn test_rlwe() {
    let mut rng = thread_rng();

    let r: PolyFF = PolyFF::random(N, &mut rng);
    let ntt_r = NTT_TABLE.transform(&r);

    let a1: PolyFF = PolyFF::random(N, &mut rng);
    let a2: PolyFF = PolyFF::random(N, &mut rng);
    let a3 = NTT_TABLE.transform(&a1) * &ntt_r;
    let a3 = NTT_TABLE.inverse_transform(&a3);

    let b1: PolyFF = PolyFF::random(N, &mut rng);
    let b2: PolyFF = PolyFF::random(N, &mut rng);
    let b3 = NTT_TABLE.transform(&b1) * &ntt_r;
    let b3 = NTT_TABLE.inverse_transform(&b3);

    let rlwe1 = Rlwe::new(a1, b1);
    let mut rlwe2 = Rlwe::new(a2, b2);
    let rlwe3 = Rlwe::new(a3, b3);
    assert!(
        rlwe1
            .clone()
            .add_element_wise(&rlwe2)
            .sub_element_wise(&rlwe1)
            == rlwe2
    );

    let mut d = NttRlwe::zero(N);
    rlwe1.mul_ntt_polynomial_inplace(&ntt_r, &NTT_TABLE, &mut d);
    d.inverse_transform_inplace(&NTT_TABLE, &mut rlwe2);
    assert!(rlwe2 == rlwe3);
}

#[inline]
fn encode(m: Inner) -> Inner {
    (m as f64 * FP as f64 / FT as f64).round() as Inner
}

#[inline]
fn decode(c: Inner) -> Inner {
    (c as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

#[inline]
fn min_to_zero(value: Inner) -> Inner {
    value.min(FP - value)
}

#[test]
fn test_rlwe_he() {
    let mut rng = rand::thread_rng();
    let chi = DiscreteGaussian::new(0., 3.2, FF::MINUS_ONE).unwrap();
    let dis = Uniform::new(0, FT);

    let v0: Vec<Inner> = dis.sample_iter(&mut rng).take(N).collect();
    let v1: Vec<Inner> = dis.sample_iter(&mut rng).take(N).collect();

    let v_add: Vec<Inner> = v0
        .iter()
        .zip(v1.iter())
        .map(|(a, b)| (*a + b) % FT)
        .collect();

    let v0 = PolyFF::new(v0.into_iter().map(encode).collect());
    let v1 = PolyFF::new(v1.into_iter().map(encode).collect());

    let s = PolyFF::random(N, &mut rng);
    let ntt_s = NTT_TABLE.transform(&s);

    let mut encrypt = |v: PolyFF| {
        let a = PolyFF::random(N, &mut rng);
        let e = PolyFF::random_with_distribution(N, &chi, &mut rng);

        let a_mul_s = NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(&a) * &ntt_s);

        let b = a_mul_s + v + e;

        Rlwe::new(a, b)
    };

    let rlwe0 = encrypt(v0);

    let rlwe1 = encrypt(v1);

    let rlwe_add = rlwe0.add_element_wise(&rlwe1);

    let a_mul_s = NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(rlwe_add.a()) * &ntt_s);

    let decrypted_add = (rlwe_add.b() - a_mul_s)
        .into_iter()
        .map(decode)
        .collect::<Vec<u32>>();

    assert_eq!(decrypted_add, v_add);
}

#[test]
fn extract_lwe_test() {
    let mut rng = thread_rng();
    let uniform = Uniform::new_inclusive(0, FF::MINUS_ONE);

    let s_vec: Vec<_> = uniform.sample_iter(&mut rng).take(N).collect();
    let a_vec: Vec<_> = uniform.sample_iter(&mut rng).take(N).collect();

    let s = PolyFF::from_slice(&s_vec);
    let a = PolyFF::new(a_vec);

    let b = NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(&a) * NTT_TABLE.transform(&s));

    let rlwe_sample = Rlwe::new(a, b);
    let lwe_sample = rlwe_sample.extract_lwe();

    let inner_a = lwe_sample
        .a()
        .iter()
        .zip(s_vec.iter())
        .fold(0, |acc, (&x, &y)| FF::MODULUS.reduce_mul_add(x, y, acc));

    assert_eq!(inner_a, lwe_sample.b());
}

#[test]
fn test_gadget_rlwe() {
    let mut rng = rand::thread_rng();

    let s = PolyFF::random(N, &mut rng);
    let ntt_s = NTT_TABLE.transform(&s);
    let gaussian = DiscreteGaussian::new(0., 1.0, FF::MINUS_ONE).unwrap();
    let basis = <NonPowOf2ApproxSignedBasis<Inner>>::new(FF::MODULUS_VALUE, BASE_BITS, None);

    let m = PolyFF::random_binary(N, &mut rng);
    let poly = PolyFF::random(N, &mut rng);
    let ntt_poly = NTT_TABLE.transform(&poly);

    let poly_mul_m = NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(&m) * &ntt_poly);

    let mut direct = NttRlwe::zero(N);

    let rlwe_m = {
        let mut temp = Rlwe::generate_random_zero_sample(&ntt_s, &gaussian, &NTT_TABLE, &mut rng);
        *temp.b_mut() += &m;
        temp
    };

    rlwe_m.mul_ntt_polynomial_inplace(&ntt_poly, &NTT_TABLE, &mut direct);

    let bad_rlwe_mul = direct.to_rlwe(&NTT_TABLE);

    let bad_mul = bad_rlwe_mul.b()
        - NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(bad_rlwe_mul.a()) * &ntt_s);

    let gadget_rlwe = GadgetRlwe::generate_random_poly_sample(
        &ntt_s, &m, &basis, &gaussian, &NTT_TABLE, &mut rng,
    );

    let good_rlwe_mul = gadget_rlwe.mul_polynomial(&poly, &NTT_TABLE);
    let good_mul = good_rlwe_mul.b()
        - NTT_TABLE.inverse_transform_inplace(NTT_TABLE.transform(good_rlwe_mul.a()) * &ntt_s);

    let diff: Vec<Inner> = (poly_mul_m.clone() - &good_mul)
        .into_iter()
        .map(min_to_zero)
        .collect();

    let bad_diff: Vec<Inner> = (poly_mul_m.clone() - &bad_mul)
        .into_iter()
        .map(min_to_zero)
        .collect();

    let diff_std_dev = diff
        .into_iter()
        .fold(0., |acc, v| acc + (v as f64) * (v as f64))
        .sqrt();

    let bad_diff_std_dev = bad_diff
        .into_iter()
        .fold(0., |acc, v| acc + (v as f64) * (v as f64))
        .sqrt();

    println!("diff_std_dev={}", diff_std_dev);
    println!("bad_diff_std_dev={}", bad_diff_std_dev);
    assert!(diff_std_dev < bad_diff_std_dev);

    let decrypted: Vec<Inner> = good_mul.into_iter().map(decode).collect();
    let decoded: Vec<Inner> = poly_mul_m.into_iter().map(decode).collect();
    assert_eq!(decrypted, decoded);
}

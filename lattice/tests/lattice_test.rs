use algebra::derive::{Field, Prime, Random, Ring, NTT};
use algebra::field::{BarrettConfig, FieldDistribution, NTTField};
use algebra::polynomial::{Poly, Polynomial};
use algebra::ring::Ring;
use lattice::*;
use rand::prelude::*;
use rand_distr::{Standard, Uniform};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
#[modulus = 512]
pub struct R512(u32);

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct Fp32(u32);

type Inner = u32; // inner type
type FF = Fp32; // field type
type RR = R512; // ring type
type PolyFF = Polynomial<FF>;

const LOG_N: usize = 3;
const N: usize = 1 << LOG_N; // length
const B: u32 = 1 << 3; // base

const FP: Inner = FF::BARRETT_MODULUS.value(); // ciphertext space
const FT: Inner = 4; // message space

#[test]
fn test_lwe() {
    let rng = &mut rand::thread_rng();

    let a1 = rng.sample_iter(Standard).take(N).collect::<Vec<RR>>();
    let a2 = rng.sample_iter(Standard).take(N).collect::<Vec<RR>>();
    let a3 = a1
        .iter()
        .zip(a2.iter())
        .map(|(u, v)| *u + v)
        .collect::<Vec<RR>>();

    let b1: RR = rng.gen();
    let b2: RR = rng.gen();
    let b3: RR = b1 + b2;

    let lwe1 = LWE::new(a1, b1);
    let lwe2 = LWE::new(a2, b2);
    let lwe3 = LWE::new(a3, b3);
    assert_eq!(lwe1.clone().add_component_wise(&lwe2), lwe3);
    assert_eq!(lwe3.clone().sub_component_wise(&lwe2), lwe1);
}

#[test]
fn test_lwe_he() {
    const RP: Inner = RR::max().0 + 1;
    const RT: Inner = 4;

    #[inline]
    fn encode(m: Inner) -> RR {
        RR::new((m as f64 * RP as f64 / RT as f64).round() as Inner)
    }

    #[inline]
    fn decode(c: RR) -> Inner {
        (c.inner() as f64 * RT as f64 / RP as f64).round() as Inner % RT
    }

    let rng = &mut rand::thread_rng();

    let chi = RR::normal_distribution(0., 3.2).unwrap();

    #[inline]
    fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
        u.iter()
            .zip(v.iter())
            .fold(R::zero(), |acc, (x, y)| acc + *x * y)
    }

    let v0: Inner = rng.gen_range(0..RT);
    let v1: Inner = rng.gen_range(0..RT);

    let s = rng.sample_iter(Standard).take(N).collect::<Vec<RR>>();

    let lwe1 = {
        let a = rng.sample_iter(Standard).take(N).collect::<Vec<RR>>();
        let b: RR = dot_product(&a, &s) + encode(v0) + chi.sample(rng);

        LWE::new(a, b)
    };

    let lwe2 = {
        let a = rng.sample_iter(Standard).take(N).collect::<Vec<RR>>();
        let b: RR = dot_product(&a, &s) + encode(v1) + chi.sample(rng);

        LWE::new(a, b)
    };

    let ret = lwe1.add_component_wise(&lwe2);
    let decrypted = decode(ret.b() - dot_product(ret.a(), &s));
    assert_eq!(decrypted, (v0 + v1) % RT);
}

#[test]
fn test_rlwe() {
    let rng = &mut rand::thread_rng();

    let r: PolyFF = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let a1: PolyFF = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let a2: PolyFF = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let a3: PolyFF = &a1 * &r;

    let b1: PolyFF = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let b2: PolyFF = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let b3: PolyFF = &b1 * &r;

    let rlwe1 = RLWE::new(a1, b1);
    let rlwe2 = RLWE::new(a2, b2);
    let rlwe3 = RLWE::new(a3, b3);
    assert_eq!(
        rlwe1
            .clone()
            .add_element_wise(&rlwe2)
            .sub_element_wise(&rlwe1),
        rlwe2
    );
    assert_eq!(rlwe1.mul_with_polynomial(&r), rlwe3);
}

#[inline]
fn encode(m: Inner) -> FF {
    FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
}

#[inline]
fn decode(c: FF) -> Inner {
    (c.inner() as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

#[inline]
fn min_to_zero(value: FF) -> Inner {
    value.inner().min(FP - value.inner())
}

#[test]
fn test_rlwe_he() {
    let rng = &mut rand::thread_rng();
    let chi = FF::normal_distribution(0., 3.2).unwrap();
    let dis = Uniform::new(0, FT);

    let v0: Vec<Inner> = rng.sample_iter(dis).take(N).collect();
    let v1: Vec<Inner> = rng.sample_iter(dis).take(N).collect();

    let v_add: Vec<Inner> = v0
        .iter()
        .zip(v1.iter())
        .map(|(a, b)| (*a + b) % FT)
        .collect();

    let v0 = PolyFF::new(v0.into_iter().map(encode).collect());
    let v1 = PolyFF::new(v1.into_iter().map(encode).collect());

    let s = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let rlwe0 = {
        let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
        let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
        let b = &a * &s + v0 + e;
        RLWE::new(a, b)
    };

    let rlwe1 = {
        let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
        let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
        let b = &a * &s + v1 + e;
        RLWE::new(a, b)
    };

    let rlwe_add = rlwe0.add_element_wise(&rlwe1);

    let decrypted_add = (rlwe_add.b() - rlwe_add.a() * &s)
        .into_iter()
        .map(decode)
        .collect::<Vec<u32>>();

    assert_eq!(decrypted_add, v_add);
}

#[test]
fn extract_lwe_test() {
    let rng = &mut thread_rng();
    let s_vec: Vec<FF> = rng.sample_iter(Standard).take(N).collect();
    let a_vec: Vec<FF> = rng.sample_iter(Standard).take(N).collect();

    let s = PolyFF::from_slice(&s_vec);
    let a = PolyFF::new(a_vec);

    let b = &a * &s;

    let rlwe_sample = RLWE::new(a, b);
    let lwe_sample = rlwe_sample.extract_lwe();

    let inner_a = lwe_sample
        .a()
        .iter()
        .zip(s_vec.iter())
        .fold(FF::new(0), |acc, (&x, &y)| acc + x * y);

    assert_eq!(inner_a, lwe_sample.b());
}

#[test]
fn test_gadget_rlwe() {
    let rng = &mut rand::thread_rng();
    let chi = FF::normal_distribution(0., 3.2).unwrap();

    let m = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let poly = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let poly_mul_m = &poly * &m;

    let s = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let decompose_len = FF::decompose_len(B);

    let m_base_power = (0..decompose_len)
        .map(|i| {
            let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
            let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
            let b = &a * &s + m.mul_scalar(B.pow(i as u32)) + e;

            RLWE::new(a, b)
        })
        .collect::<Vec<RLWE<FF>>>();

    let bad_rlwe_mul = m_base_power[0].clone().mul_with_polynomial(&poly);
    let bad_mul = bad_rlwe_mul.b() - bad_rlwe_mul.a() * &s;

    let gadget_rlwe = GadgetRLWE::new(m_base_power, B);

    let good_rlwe_mul = gadget_rlwe.mul_with_polynomial(&poly);
    let good_mul = good_rlwe_mul.b() - good_rlwe_mul.a() * s;

    let diff: Vec<Inner> = (&poly_mul_m - &good_mul)
        .into_iter()
        .map(min_to_zero)
        .collect();

    let bad_diff: Vec<Inner> = (&poly_mul_m - &bad_mul)
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

    assert!(diff_std_dev < bad_diff_std_dev);

    let decrypted: Vec<Inner> = good_mul.into_iter().map(decode).collect();
    let decoded: Vec<Inner> = poly_mul_m.into_iter().map(decode).collect();
    assert_eq!(decrypted, decoded);
}

#[test]
fn test_rgsw_mul_rlwe() {
    let rng = &mut rand::thread_rng();
    let ternary = FF::ternary_distribution();
    let chi = FF::normal_distribution(0., 3.2).unwrap();

    let m0 = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let m1 = PolyFF::new(rng.sample_iter(ternary).take(N).collect());

    let m0m1 = &m0 * &m1;

    let s = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let decompose_len = FF::decompose_len(B);

    let rgsw = {
        let m1_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + m1.mul_scalar(B.pow(i as u32)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm1_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + e;

                RLWE::new(a + m1.mul_scalar(B.pow(i as u32)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm1_base_power, B),
            GadgetRLWE::new(m1_base_power, B),
        )
    };

    let (rlwe, _e) = {
        let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
        let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
        let b = &a * &s + m0 + &e;

        (RLWE::new(a, b), e)
    };

    let rlwe_mul = rgsw.mul_with_rlwe(&rlwe);
    let decrypt_mul = rlwe_mul.b() - rlwe_mul.a() * &s;

    let decoded_m0m1: Vec<u32> = m0m1.into_iter().map(decode).collect();
    let decoded_decrypt: Vec<u32> = decrypt_mul.into_iter().map(decode).collect();
    assert_eq!(decoded_m0m1, decoded_decrypt);
}

#[test]
fn test_rgsw_mul_rgsw() {
    let rng = &mut rand::thread_rng();
    let ternary = FF::ternary_distribution();
    let chi = FF::normal_distribution(0., 3.2).unwrap();

    let m0 = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let m1 = PolyFF::new(rng.sample_iter(ternary).take(N).collect());

    let m0m1 = &m0 * &m1;

    let s = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let decompose_len = FF::decompose_len(B);

    let rgsw_m1 = {
        let m1_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + m1.mul_scalar(B.pow(i as u32)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm1_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + e;

                RLWE::new(a + m1.mul_scalar(B.pow(i as u32)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm1_base_power, B),
            GadgetRLWE::new(m1_base_power, B),
        )
    };

    let rgsw_m0 = {
        let m0_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + m0.mul_scalar(B.pow(i as u32)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm0_base_power = (0..decompose_len)
            .map(|i| {
                let a = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
                let e = PolyFF::new(rng.sample_iter(chi).take(N).collect());
                let b = &a * &s + e;

                RLWE::new(a + m0.mul_scalar(B.pow(i as u32)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm0_base_power, B),
            GadgetRLWE::new(m0_base_power, B),
        )
    };

    let rgsw_m0m1 = rgsw_m0.mul_with_rgsw(&rgsw_m1);

    let rlwe_m0m1 = &rgsw_m0m1.c_m().data()[0];
    let decrypted_m0m1 = rlwe_m0m1.b() - rlwe_m0m1.a() * &s;

    let decoded_m0m1: Vec<u32> = m0m1.iter().copied().map(decode).collect();
    let decoded_decrypt: Vec<u32> = decrypted_m0m1.into_iter().map(decode).collect();
    assert_eq!(decoded_m0m1, decoded_decrypt);

    let rlwe_neg_sm0m1 = &rgsw_m0m1.c_neg_s_m().data()[0];
    let decrypted_neg_sm0m1 = rlwe_neg_sm0m1.b() - rlwe_neg_sm0m1.a() * &s;
    let neg_sm0m1 = m0m1 * &s.mul_scalar(FP - 1);

    let decoded_neg_sm0m1: Vec<u32> = neg_sm0m1.iter().copied().map(decode).collect();
    let decoded_decrypt_neg_sm0m1: Vec<u32> = decrypted_neg_sm0m1.into_iter().map(decode).collect();
    assert_eq!(decoded_neg_sm0m1, decoded_decrypt_neg_sm0m1);
}
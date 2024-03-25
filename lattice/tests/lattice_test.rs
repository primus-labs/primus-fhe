use algebra::derive::{Field, Prime, Random, NTT};
use algebra::modulus::PowOf2Modulus;
use algebra::reduce::{AddReduce, MulReduce, SubReduce};
use algebra::{Basis, Field, ModulusConfig, Polynomial, Random};
use lattice::*;
use rand::prelude::*;
use rand_distr::{Standard, Uniform};

#[derive(Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

type Inner = u32; // inner type
type FF = Fp32; // field type
type PolyFF = Polynomial<FF>;

const RR: Inner = 1024;

const LOG_N: usize = 3;
const N: usize = 1 << LOG_N; // length
const BITS: u32 = 3;
const B: usize = 1 << BITS; // base

const FP: Inner = FF::MODULUS.value(); // ciphertext space
const FT: Inner = 4; // message space

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
        .map(|(u, v)| u.add_reduce(*v, modulus))
        .collect::<Vec<Inner>>();

    let b1: Inner = rng.sample(dis);
    let b2: Inner = rng.sample(dis);
    let b3: Inner = b1.add_reduce(b2, modulus);

    let lwe1 = LWE::new(a1, b1);
    let lwe2 = LWE::new(a2, b2);
    let lwe3 = LWE::new(a3, b3);
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

    let rng = &mut rand::thread_rng();

    let dis = Uniform::new(0u32, RR);
    let modulus = <PowOf2Modulus<u32>>::new(RR);

    let v0: Inner = rng.gen_range(0..RT);
    let v1: Inner = rng.gen_range(0..RT);

    let s = rng.sample_iter(dis).take(N).collect::<Vec<Inner>>();

    let lwe1 = {
        let a = rng.sample_iter(dis).take(N).collect::<Vec<Inner>>();
        let b = a
            .iter()
            .zip(&s)
            .fold(0, |acc, (&x, &y)| {
                x.mul_reduce(y, modulus).add_reduce(acc, modulus)
            })
            .add_reduce(encode(v0), modulus)
            .add_reduce(rng.gen_range(0..EMAX), modulus);

        LWE::new(a, b)
    };

    let lwe2 = {
        let a = rng.sample_iter(Standard).take(N).collect::<Vec<Inner>>();

        let b = a
            .iter()
            .zip(&s)
            .fold(0, |acc, (&x, &y)| {
                x.mul_reduce(y, modulus).add_reduce(acc, modulus)
            })
            .add_reduce(encode(v1), modulus)
            .add_reduce(rng.gen_range(0..EMAX), modulus);

        LWE::new(a, b)
    };

    let ret = lwe1.add_component_wise(&lwe2);
    let decrypted = decode(ret.b().sub_reduce(
        ret.a().iter().zip(&s).fold(0, |acc, (&x, &y)| {
            x.mul_reduce(y, modulus).add_reduce(acc, modulus)
        }),
        modulus,
    ));
    assert_eq!(decrypted, (v0 + v1) % RT);
}

#[test]
fn test_rlwe() {
    let mut rng = rand::thread_rng();

    let r: PolyFF = PolyFF::random(N, &mut rng);

    let a1: PolyFF = PolyFF::random(N, &mut rng);
    let a2: PolyFF = PolyFF::random(N, &mut rng);
    let a3: PolyFF = &a1 * &r;

    let b1: PolyFF = PolyFF::random(N, &mut rng);
    let b2: PolyFF = PolyFF::random(N, &mut rng);
    let b3: PolyFF = &b1 * &r;

    let rlwe1 = RLWE::new(a1, b1);
    let mut rlwe2 = RLWE::new(a2, b2);
    let rlwe3 = RLWE::new(a3, b3);
    assert_eq!(
        rlwe1
            .clone()
            .add_element_wise(&rlwe2)
            .sub_element_wise(&rlwe1),
        rlwe2
    );
    let r = r.into_ntt_polynomial();
    let mut d = NTTRLWE::zero(N);
    rlwe1.mul_ntt_polynomial_inplace(&r, &mut d);
    d.inverse_transform_inplace(&mut rlwe2);
    assert_eq!(rlwe2, rlwe3);
}

#[inline]
fn encode(m: Inner) -> FF {
    FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
}

#[inline]
fn decode(c: FF) -> Inner {
    (c.get() as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

#[inline]
fn min_to_zero(value: FF) -> Inner {
    value.get().min(FP - value.get())
}

#[test]
fn test_rlwe_he() {
    let mut rng = rand::thread_rng();
    let chi = FF::gaussian_sampler(0., 3.2).unwrap();
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

    let rlwe0 = {
        let a = PolyFF::random(N, &mut rng);
        let e = PolyFF::random_with_distribution(N, &mut rng, chi);
        let b = &a * &s + v0 + e;
        RLWE::new(a, b)
    };

    let rlwe1 = {
        let a = PolyFF::random(N, &mut rng);
        let e = PolyFF::random_with_distribution(N, &mut rng, chi);
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
        .fold(FF::new(0), |acc, (&x, y)| acc + x * y);

    assert_eq!(inner_a, lwe_sample.b());
}

#[test]
fn test_gadget_rlwe() {
    let mut rng = rand::thread_rng();
    let chi = FF::gaussian_sampler(0., 3.2).unwrap();

    let m = PolyFF::random(N, &mut rng);
    let poly = PolyFF::random(N, &mut rng);

    let poly_mul_m = &poly * &m;

    let s = PolyFF::random(N, &mut rng);
    let basis = <Basis<Fp32>>::new(BITS);

    let m_base_power = (0..basis.decompose_len())
        .map(|i| {
            let a = PolyFF::random(N, &mut rng);
            let e = PolyFF::random_with_distribution(N, &mut rng, chi);
            let b = &a * &s + m.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)) + e;

            RLWE::new(a, b)
        })
        .collect::<Vec<RLWE<FF>>>();

    let np = poly.clone().into_ntt_polynomial();
    let mut d = NTTRLWE::zero(N);

    m_base_power[0]
        .clone()
        .mul_ntt_polynomial_inplace(&np, &mut d);

    let bad_rlwe_mul = RLWE::from(d);
    let bad_mul = bad_rlwe_mul.b() - bad_rlwe_mul.a() * &s;

    let gadget_rlwe = GadgetRLWE::new(m_base_power, basis);

    let good_rlwe_mul = gadget_rlwe.mul_polynomial(&poly);
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
    let mut rng = rand::thread_rng();
    let ternary = FF::ternary_sampler();
    let chi = FF::gaussian_sampler(0., 3.2).unwrap();

    let m0 = PolyFF::random(N, &mut rng);
    let m1 = PolyFF::random_with_distribution(N, &mut rng, ternary);

    let m0m1 = &m0 * &m1;

    let s = PolyFF::random(N, &mut rng);

    let basis = <Basis<Fp32>>::new(BITS);

    let rgsw = {
        let m1_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + m1.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm1_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + e;

                RLWE::new(a + m1.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm1_base_power, basis),
            GadgetRLWE::new(m1_base_power, basis),
        )
    };

    let (rlwe, _e) = {
        let a = PolyFF::random(N, &mut rng);
        let e = PolyFF::random_with_distribution(N, &mut rng, chi);
        let b = &a * &s + m0 + &e;

        (RLWE::new(a, b), e)
    };

    let rlwe_mul = rlwe.mul_small_rgsw(&rgsw);
    let decrypt_mul = rlwe_mul.b() - rlwe_mul.a() * &s;

    let decoded_m0m1: Vec<u32> = m0m1.into_iter().map(decode).collect();
    let decoded_decrypt: Vec<u32> = decrypt_mul.into_iter().map(decode).collect();
    assert_eq!(decoded_m0m1, decoded_decrypt);
}

#[test]
fn test_rgsw_mul_rgsw() {
    let mut rng = rand::thread_rng();
    let ternary = FF::ternary_sampler();
    let chi = FF::gaussian_sampler(0., 3.2).unwrap();

    let m0 = PolyFF::random(N, &mut rng);
    let m1 = PolyFF::random_with_distribution(N, &mut rng, ternary);

    let m0m1 = &m0 * &m1;

    let s = PolyFF::random(N, &mut rng);

    let basis = <Basis<Fp32>>::new(BITS);

    let rgsw_m1 = {
        let m1_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + m1.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm1_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + e;

                RLWE::new(a + m1.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm1_base_power, basis),
            GadgetRLWE::new(m1_base_power, basis),
        )
    };

    let rgsw_m0 = {
        let m0_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + m0.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<FF>>>();

        let neg_sm0_base_power = (0..basis.decompose_len())
            .map(|i| {
                let a = PolyFF::random(N, &mut rng);
                let e = PolyFF::random_with_distribution(N, &mut rng, chi);
                let b = &a * &s + e;

                RLWE::new(a + m0.mul_scalar(Fp32::new(B.pow(i as u32) as Inner)), b)
            })
            .collect::<Vec<RLWE<FF>>>();

        RGSW::new(
            GadgetRLWE::new(neg_sm0_base_power, basis),
            GadgetRLWE::new(m0_base_power, basis),
        )
    };

    let rgsw_m0m1 = rgsw_m0.mul_small_rgsw(&rgsw_m1);

    let rlwe_m0m1 = &rgsw_m0m1.c_m().data()[0];
    let decrypted_m0m1 = rlwe_m0m1.b() - rlwe_m0m1.a() * &s;

    let decoded_m0m1: Vec<u32> = m0m1.copied_iter().map(decode).collect();
    let decoded_decrypt: Vec<u32> = decrypted_m0m1.into_iter().map(decode).collect();
    assert_eq!(decoded_m0m1, decoded_decrypt);

    let rlwe_neg_sm0m1 = &rgsw_m0m1.c_neg_s_m().data()[0];
    let decrypted_neg_sm0m1 = rlwe_neg_sm0m1.b() - rlwe_neg_sm0m1.a() * &s;
    let neg_sm0m1 = m0m1 * &s.mul_scalar(Fp32::new(FP - 1));

    let decoded_neg_sm0m1: Vec<u32> = neg_sm0m1.copied_iter().map(decode).collect();
    let decoded_decrypt_neg_sm0m1: Vec<u32> = decrypted_neg_sm0m1.into_iter().map(decode).collect();
    assert_eq!(decoded_neg_sm0m1, decoded_decrypt_neg_sm0m1);
}

use algebra::{
    derive::{Field, Prime, Random, Ring, NTT},
    field::{BarrettConfig, Field, NTTField},
    polynomial::{NTTPolynomial, Poly, Polynomial},
};
use rand::{distributions::Uniform, prelude::*, thread_rng};
use rand_distr::Standard;

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct Fp32(u32);

type Inner = u32; // inner type
type FF = Fp32; // field type
type PolyFF = Polynomial<FF>;
type NTTPolyFF = NTTPolynomial<FF>;

const LOG_N: usize = 3;
const N: usize = 1 << LOG_N; // length
const B: Inner = 1 << 3; // base
const P: Inner = FF::BARRETT_MODULUS.value(); // ciphertext space

#[test]
fn test_transform() {
    FF::init_ntt_table(&[LOG_N as u32]).unwrap();

    let distr = Uniform::new(0, P);
    let rng = thread_rng();

    let coeffs = rng.sample_iter(distr).take(N).map(FF::new).collect();

    let a = PolyFF::new(coeffs);
    let b = a.clone().to_ntt_polynomial();
    let c = b.clone().to_native_polynomial();
    let d = c.clone().to_ntt_polynomial();
    assert_eq!(a, c);
    assert_eq!(b, d);
}

#[test]
fn test_native_poly() {
    let a = PolyFF::new(vec![FF::new(1), FF::new(P - 1)]);
    let b = PolyFF::new(vec![FF::new(P - 1), FF::new(1)]);

    let add_result = PolyFF::new(vec![FF::new(0), FF::new(0)]);
    assert_eq!(&a + &b, add_result);
    assert_eq!(&a + b.clone(), add_result);
    assert_eq!(a.clone() + &b, add_result);
    assert_eq!(a.clone() + b.clone(), add_result);

    let sub_result = PolyFF::new(vec![FF::new(2), FF::new(P - 2)]);
    assert_eq!(&a - &b, sub_result);
    assert_eq!(&a - b.clone(), sub_result);
    assert_eq!(a.clone() - &b, sub_result);
    assert_eq!(a.clone() - b.clone(), sub_result);

    assert_eq!(-a, b);
}

#[test]
fn test_native_poly_mul() {
    FF::init_ntt_table(&[LOG_N as u32]).unwrap();

    let distr = Uniform::new(0, P);
    let mut rng = thread_rng();

    let coeffs1: Vec<FF> = distr.sample_iter(&mut rng).take(N).map(FF::new).collect();

    let coeffs2: Vec<FF> = distr.sample_iter(&mut rng).take(N).map(FF::new).collect();

    let a = PolyFF::new(coeffs1);
    let b = PolyFF::new(coeffs2);

    let mul_result = simple_mul(&a, &b);
    assert_eq!(a * b, mul_result);
}

fn simple_mul<F: Field>(lhs: &Polynomial<F>, rhs: &Polynomial<F>) -> Polynomial<F> {
    assert_eq!(lhs.coeff_count(), rhs.coeff_count());
    let coeff_count = lhs.coeff_count();

    let mut result = vec![F::zero(); coeff_count];
    let poly1: &[F] = lhs.as_ref();
    let poly2: &[F] = rhs.as_ref();

    for i in 0..coeff_count {
        for j in 0..=i {
            result[i] += poly1[j] * poly2[i - j];
        }
    }

    // mod (x^n + 1)
    for i in coeff_count..coeff_count * 2 - 1 {
        let k = i - coeff_count;
        for j in i - coeff_count + 1..coeff_count {
            result[k] -= poly1[j] * poly2[i - j]
        }
    }

    Polynomial::<F>::new(result)
}

#[test]
fn test_poly_decompose() {
    let rng = &mut thread_rng();
    let poly = PolyFF::new(Standard.sample_iter(rng).take(N).collect());
    let decompose = poly.decompose(B);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(PolyFF::zero_with_coeff_count(N), |acc, (i, d)| {
            acc + d.mul_scalar(B.pow(i as u32))
        });
    assert_eq!(compose, poly);
}

#[test]
fn test_poly_decompose_mul() {
    let rng = &mut thread_rng();

    let poly1 = PolyFF::new(rng.sample_iter(Standard).take(N).collect());
    let poly2 = PolyFF::new(rng.sample_iter(Standard).take(N).collect());

    let mul_result = &poly1 * &poly2;

    let decompose = poly1.decompose(B);
    let compose_mul_result = decompose
        .into_iter()
        .enumerate()
        .fold(PolyFF::zero_with_coeff_count(N), |acc, (i, d)| {
            acc + d * poly2.mul_scalar(B.pow(i as u32))
        });
    assert_eq!(compose_mul_result, mul_result);
}

#[test]
fn test_ntt_poly() {
    let a = NTTPolyFF::new(vec![FF::new(1), FF::new(P - 1)]);
    let b = NTTPolyFF::new(vec![FF::new(P - 1), FF::new(1)]);

    let mul_result = NTTPolyFF::new(vec![FF::new(P - 1), FF::new(P - 1)]);
    assert_eq!(&a * &b, mul_result);
    assert_eq!(&a * b.clone(), mul_result);
    assert_eq!(a.clone() * &b, mul_result);
    assert_eq!(a.clone() * b.clone(), mul_result);

    let add_result = NTTPolyFF::new(vec![FF::new(0), FF::new(0)]);
    assert_eq!(&a + &b, add_result);
    assert_eq!(&a + b.clone(), add_result);
    assert_eq!(a.clone() + &b, add_result);
    assert_eq!(a.clone() + b.clone(), add_result);

    let sub_result = NTTPolyFF::new(vec![FF::new(2), FF::new(P - 2)]);
    assert_eq!(&a - &b, sub_result);
    assert_eq!(&a - b.clone(), sub_result);
    assert_eq!(a.clone() - &b, sub_result);
    assert_eq!(a.clone() - b.clone(), sub_result);

    assert_eq!(-a, b);
}

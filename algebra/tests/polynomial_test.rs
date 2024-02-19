use algebra::{
    derive::{Field, Prime, Random, NTT},
    Basis, Field, ModulusConfig, NTTField, NTTPolynomial, Polynomial,
};
use rand::thread_rng;

#[derive(Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

type Inner = u32; // inner type
type FF = Fp32; // field type
type PolyFF = Polynomial<FF>;
type NTTPolyFF = NTTPolynomial<FF>;

const LOG_N: usize = 3;
const N: usize = 1 << LOG_N; // length
const BITS: u32 = 3;
const B: usize = 1 << BITS; // base
const P: Inner = FF::MODULUS.value(); // ciphertext space

#[test]
fn test_transform() {
    FF::init_ntt_table(&[LOG_N as u32]).unwrap();

    let a = PolyFF::random(N, thread_rng());
    let b = a.clone().into_ntt_polynomial();
    let c = b.clone().into_native_polynomial();
    let d = c.clone().into_ntt_polynomial();
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

    let mut rng = thread_rng();

    let a = PolyFF::random(N, &mut rng);
    let b = PolyFF::random(N, &mut rng);

    let mul_result = simple_mul(&a, &b);
    assert_eq!(&a * &b, mul_result);

    let b = b.into_ntt_polynomial();
    assert_eq!(&a * &b, mul_result);
    assert_eq!(&a * b.clone(), mul_result);

    let mul_result = mul_result.into_ntt_polynomial();
    assert_eq!(&b * &a, mul_result);
    assert_eq!(b * a, mul_result);
}

fn simple_mul<F: Field>(lhs: &Polynomial<F>, rhs: &Polynomial<F>) -> Polynomial<F> {
    assert_eq!(lhs.coeff_count(), rhs.coeff_count());
    let coeff_count = lhs.coeff_count();

    let mut result = vec![F::ZERO; coeff_count];
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
    let poly = PolyFF::random(N, rng);
    let basis = <Basis<Fp32>>::new(BITS);
    let decompose = poly.clone().decompose(basis);
    let compose = decompose.into_iter().enumerate().fold(
        PolyFF::zero_with_coeff_count(N),
        |acc, (i, mut d)| {
            d.mul_scalar_inplace(B.pow(i as u32) as Inner);
            acc + d
        },
    );
    assert_eq!(compose, poly);
}

#[test]
fn test_poly_decompose_mul() {
    let mut rng = thread_rng();

    let poly1 = PolyFF::random(N, &mut rng);
    let poly2 = PolyFF::random(N, &mut rng);

    let mul_result = &poly1 * &poly2;

    let basis = <Basis<Fp32>>::new(BITS);
    let decompose = poly1.decompose(basis);
    let compose_mul_result = decompose
        .into_iter()
        .enumerate()
        .fold(PolyFF::zero_with_coeff_count(N), |acc, (i, d)| {
            acc + d * poly2.mul_scalar(B.pow(i as u32) as Inner)
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

#[test]
fn test_poly_eval() {
    let rng = &mut thread_rng();
    let poly = PolyFF::random(N, rng);

    assert_eq!(
        poly.evaluate(FF::max()),
        poly.iter()
            .enumerate()
            .fold(FF::ZERO, |acc, (i, a)| if i & 1 == 0 {
                acc + a
            } else {
                acc - a
            })
    );
    assert_eq!(poly.evaluate(FF::ZERO), poly[0]);
    assert_eq!(
        poly.evaluate(FF::ONE),
        poly.iter().fold(FF::ZERO, |acc, a| acc + a)
    );
}

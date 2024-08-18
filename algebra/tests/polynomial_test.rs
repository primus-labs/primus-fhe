use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    transformation::{AbstractNTT, MonomialNTT},
    Basis, Field, FieldUniformSampler, ModulusConfig, NTTField, NTTPolynomial, Polynomial,
};
use num_traits::{One, Zero};
use rand::{thread_rng, Rng};
use rand_distr::Distribution;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

type Inner = u32; // inner type
type FF = Fp32; // field type
type PolyFF = Polynomial<FF>;
type NTTPolyFF = NTTPolynomial<FF>;

const LOG_N: usize = 5;
const N: usize = 1 << LOG_N; // length
const BITS: u32 = 3;
const B: usize = 1 << BITS; // base
const P: Inner = FF::MODULUS.value(); // ciphertext space

#[test]
fn test_transform() {
    FF::init_ntt_table(&[LOG_N as u32]).unwrap();

    let a = PolyFF::random(N, &mut thread_rng());
    let b = a.clone().into_ntt_polynomial();
    let c = b.clone().into_native_polynomial();
    let d = c.clone().into_ntt_polynomial();
    assert_eq!(a, c);
    assert_eq!(b, d);
}

#[test]
fn test_transform_monomial() {
    let mut rng = thread_rng();

    let uniform = <FieldUniformSampler<FF>>::new();
    let degree = rng.gen_range(0..N);
    let coeff = uniform.sample(&mut rng);
    let mut a = PolyFF::zero(N);
    let mut b = NTTPolyFF::zero(N);
    a[degree] = coeff;

    let table = Fp32::get_ntt_table(LOG_N as u32).unwrap();
    let a = table.transform_inplace(a);

    table.transform_monomial(coeff, degree, b.as_mut_slice());
    assert_eq!(a, b);

    let mut a = PolyFF::zero(N);
    let mut b = NTTPolyFF::zero(N);
    a[degree] = FF::neg_one();

    let a = table.transform_inplace(a);

    table.transform_monomial(FF::neg_one(), degree, b.as_mut_slice());
    assert_eq!(a, b);
}

#[test]
fn test_monomial_property() {
    let mut rng = thread_rng();

    let table = Fp32::get_ntt_table(LOG_N as u32).unwrap();

    let degree = rng.gen_range(0..N);

    let mut a = NTTPolyFF::zero(N);
    let mut b = NTTPolyFF::zero(N);

    table.transform_monomial(Fp32::one(), degree, a.as_mut_slice());
    table.transform_monomial(Fp32::neg_one(), degree + N, b.as_mut_slice());
    assert_eq!(a, b);

    table.transform_monomial(Fp32::neg_one(), degree, a.as_mut_slice());
    table.transform_monomial(Fp32::one(), degree + N, b.as_mut_slice());
    assert_eq!(a, b);

    let degree = rng.gen_range(N..N * 2);

    table.transform_monomial(Fp32::neg_one(), N * 2 - degree, a.as_mut_slice());
    table.transform_monomial(Fp32::one(), N * 2 - (degree - N), b.as_mut_slice());
    assert_eq!(a, b);
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
    let poly = PolyFF::random(N, rng);
    let basis = <Basis<Fp32>>::new(BITS);
    let decompose = poly.clone().decompose(basis);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(PolyFF::zero(N), |acc, (i, mut d)| {
            d.mul_scalar_assign(Fp32::new(B.pow(i as u32) as Inner));
            acc + d
        });
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
        .fold(PolyFF::zero(N), |acc, (i, d)| {
            acc + d * poly2.mul_scalar(Fp32::new(B.pow(i as u32) as u32))
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
            .fold(FF::zero(), |acc, (i, a)| if i & 1 == 0 {
                acc + a
            } else {
                acc - a
            })
    );
    assert_eq!(poly.evaluate(FF::zero()), poly[0]);
    assert_eq!(
        poly.evaluate(FF::one()),
        poly.iter().fold(FF::zero(), |acc, a| acc + a)
    );
}

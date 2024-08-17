use std::vec;

use algebra::{
    derive::{DecomposableField, Field, Prime},
    BabyBear, BabyBearExetension, Basis, DenseMultilinearExtension, DenseMultilinearExtensionBase,
    Field, FieldUniformSampler, ListOfProductsOfPolynomials, MultilinearExtension,
    MultilinearExtensionBase, UF,
};
use num_traits::{One, Zero};
use rand::thread_rng;
use rand_distr::Distribution;
use std::rc::Rc;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

fn uf_new(val: u32) -> UF<FF, EF> {
    UF::BaseField(FF::new(val))
}

#[derive(Field, DecomposableField, Prime)]
#[modulus = 132120577]
pub struct Fp32(u32);

// field type
type FF = BabyBear;
type EF = BabyBearExetension;
type PolyFF = DenseMultilinearExtensionBase<FF>;
type PolyEF = DenseMultilinearExtension<FF, EF>;

fn evaluate_mle_data_array(data: &[EF], point: &[EF]) -> EF {
    if data.len() != (1 << point.len()) {
        panic!("Data size mismatch with number of variables.")
    }
    let nv = point.len();
    let mut a = data.to_vec();

    for i in 1..nv + 1 {
        let r = point[i - 1];
        for b in 0..(1 << (nv - i)) {
            a[b] = a[b << 1] * (EF::one() - r) + a[(b << 1) + 1] * r;
        }
    }

    a[0]
}

#[test]
fn evaluate_mle_at_a_point() {
    let poly = PolyEF::from_evaluations_vec(2, field_vec! {EF; 1, 2, 3, 4});

    let point = vec![EF::new(0), EF::new(1)];
    assert_eq!(poly.evaluate(&point), EF::new(3));
}

#[test]
fn evaluate_mle_at_a_random_point() {
    let mut rng = thread_rng();
    let poly = PolyEF::random(2, &mut rng);
    let uniform = <FieldUniformSampler<EF>>::new();
    let point: Vec<_> = (0..2).map(|_| uniform.sample(&mut rng)).collect();
    assert_eq!(
        poly.evaluate(&point),
        evaluate_mle_data_array(&poly.evaluations, &point),
    );
}

#[test]
fn mle_arithmetic() {
    const NV: usize = 10;
    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<EF>>::new();
    let uniform_ff = <FieldUniformSampler<FF>>::new();
    for _ in 0..20 {
        let point: Vec<_> = (0..NV).map(|_| uniform.sample(&mut rng)).collect();
        let poly1 = PolyEF::random(NV, &mut rng);
        let poly2 = PolyEF::random(NV, &mut rng);
        let v1 = poly1.evaluate(&point);
        let v2 = poly2.evaluate(&point);
        // test add
        assert_eq!((&poly1 + &poly2).evaluate(&point), v1 + v2);
        // test sub
        assert_eq!((&poly1 - &poly2).evaluate(&point), v1 - v2);
        // test negate
        assert_eq!(-poly1.evaluate(&point), -v1);
        // test add assign
        {
            let mut poly1 = poly1.clone();
            poly1 += &poly2;
            assert_eq!(poly1.evaluate(&point), v1 + v2);
        }
        // test sub assign
        {
            let mut poly1 = poly1.clone();
            poly1 -= &poly2;
            assert_eq!(poly1.evaluate(&point), v1 - v2);
        }
        // test add assign with scalar
        {
            let mut poly1 = poly1.clone();
            let scalar = uniform.sample(&mut rng);
            poly1 += (scalar, &poly2);
            assert_eq!(poly1.evaluate(&point), v1 + scalar * v2);
        }
        // test additive identity
        {
            assert_eq!(&poly1 + &PolyEF::zero(), poly1);
            assert_eq!((&PolyEF::zero() + &poly1), poly1);
        }

        // test decomposition of mle
        {
            let poly_decomposed = PolyFF::random(NV, &mut rng);
            let base_len = 3;
            let base = FF::new(1 << base_len);
            let basis = <Basis<FF>>::new(base_len);
            let bits_len = basis.decompose_len();
            let decomposed_polys = poly_decomposed.get_decomposed_mles(base_len, bits_len as u32);
            let point: Vec<_> = (0..NV).map(|_| uniform_ff.sample(&mut rng)).collect();

            // base_pow = [1, B, ..., B^{l-1}]
            let mut base_pow = vec![FF::one(); bits_len];
            base_pow.iter_mut().fold(FF::one(), |acc, pow| {
                *pow *= acc;
                acc * base
            });
            let evaluation = decomposed_polys
                .iter()
                .zip(base_pow.into_iter())
                .fold(FF::zero(), |acc, (bit, base_pow)| {
                    acc + bit.evaluate(&point) * base_pow
                });
            assert_eq!(poly_decomposed.evaluate(&point), evaluation);
        }
    }
}

#[test]
fn trivial_decomposed_mles() {
    let base_len = 2; // i.e. base = 4
    let base = FF::new(1 << base_len);
    let bits_len = 3;
    let num_vars = 2;

    let val = field_vec!(FF; 0b001101, 0b100011, 0b101100, 0b111110);
    let poly = DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, val);
    let decomposed_polys = poly.get_decomposed_mles(base_len, bits_len);

    let uniform = <FieldUniformSampler<FF>>::new();
    let point: Vec<FF> = (0..num_vars)
        .map(|_| uniform.sample(&mut thread_rng()))
        .collect();

    // base_pow = [1, B, ..., B^{l-1}]
    let mut base_pow = vec![FF::one(); bits_len as usize];
    base_pow.iter_mut().fold(FF::one(), |acc, pow| {
        *pow *= acc;
        acc * base
    });
    let evaluation = decomposed_polys
        .iter()
        .zip(base_pow)
        .fold(FF::zero(), |acc, (bit, base_pow)| {
            acc + bit.evaluate(&point) * base_pow
        });

    assert_eq!(poly.evaluate(&point), evaluation);
}

#[test]
fn evaluate_lists_of_products_at_a_point() {
    let nv = 2;
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    let products = vec![field_vec!(EF; 1, 2, 3, 4), field_vec!(EF; 5, 4, 2, 9)];
    let products: Vec<Rc<DenseMultilinearExtension<FF, EF>>> = products
        .into_iter()
        .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();
    let coeff = EF::new(4);
    poly.add_product(products, coeff);

    let point = field_vec!(EF; 0, 1);
    assert_eq!(poly.evaluate(&point), EF::new(24));
}

#[test]
fn evaluate_lists_of_products_with_op_at_a_point() {
    let nv = 2;
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    let products = vec![field_vec!(EF; 1, 2, 3, 4), field_vec!(EF; 1, 2, 3, 4)];
    let products: Vec<Rc<DenseMultilinearExtension<FF, EF>>> = products
        .into_iter()
        .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();
    let coeff = EF::new(4);

    let op_coefficient = vec![(uf_new(2), uf_new(0)), (uf_new(1), uf_new(3))];
    // coeff \cdot [2f \cdot (g + 3)]
    poly.add_product_with_linear_op(products, &op_coefficient, coeff);
    // 4 * [2*2 * (2+3)] = 80
    let point = field_vec!(EF; 1, 0);
    assert_eq!(poly.evaluate(&point), EF::new(80));
}

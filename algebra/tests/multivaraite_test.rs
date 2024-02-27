use std::vec;

use algebra::{
    derive::{Field, Prime, Random},
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension, Random,
};
use num_traits::Zero;
use rand::thread_rng;
use rand_distr::Distribution;
use std::rc::Rc;

macro_rules! field_vec {
    ($t:ident; $elem:expr; $n:expr)=>{
        vec![$t::new($elem);$n]
    };
    ($t:ident; $($x:expr),+ $(,)?) => {
        vec![$($t::new($x)),+]
    }
}

#[derive(Field, Random, Prime)]
#[modulus = 132120577]
pub struct Fp32(u32);

// field type
type FF = Fp32;
type PolyFf = DenseMultilinearExtension<FF>;

fn evaluate_mle_data_arry<F: Field>(data: &[F], point: &[F]) -> F {
    if data.len() != (1 << point.len()) {
        panic!("Data size mismatch with number of variables.")
    }
    let nv = point.len();
    let mut a = data.to_vec();

    for i in 1..nv + 1 {
        let r = point[i - 1];
        for b in 0..(1 << (nv - i)) {
            a[b] = a[b << 1] * (F::one() - r) + a[(b << 1) + 1] * r;
        }
    }

    a[0]
}

#[test]
fn evaluate_mle_at_a_point() {
    let poly = PolyFf::from_evaluations_vec(2, field_vec! {FF; 1, 2, 3, 4});

    let point = vec![FF::new(0), FF::new(1)];
    assert_eq!(poly.evaluate(&point), FF::new(3));
}

#[test]
fn evaluate_mle_at_a_random_point() {
    let mut rng = thread_rng();
    let poly = PolyFf::random(2, &mut rng);
    let point: Vec<_> = (0..2).map(|_| FF::random(&mut rng)).collect();
    assert_eq!(
        poly.evaluate(&point),
        evaluate_mle_data_arry(&poly.evaluations, &point),
    );
}

#[test]
fn mle_arithmetic() {
    const NV: usize = 10;
    let mut rng = thread_rng();
    for _ in 0..20 {
        let point: Vec<_> = (0..NV).map(|_| FF::random(&mut rng)).collect();
        let poly1 = PolyFf::random(NV, &mut rng);
        let poly2 = PolyFf::random(NV, &mut rng);
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
            let scalar = FF::random(&mut rng);
            poly1 += (scalar, &poly2);
            assert_eq!(poly1.evaluate(&point), v1 + scalar * v2);
        }
        // test additive identity
        {
            assert_eq!(&poly1 + &PolyFf::zero(), poly1);
            assert_eq!((&PolyFf::zero() + &poly1), poly1);
        }
    }
}

#[test]
fn evaluate_lists_of_products_at_a_point() {
    let nv = 2;
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    let products = vec![field_vec!(FF; 1, 2, 3, 4), field_vec!(FF; 5, 4, 2, 9)];
    let products: Vec<Rc<DenseMultilinearExtension<FF>>> = products
        .into_iter()
        .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();
    let coeff = FF::new(4);
    poly.add_product(products, coeff);

    let point = field_vec!(FF; 0, 1);
    assert_eq!(poly.evaluate(&point), FF::new(24));
}

#[allow(dead_code)]
fn random_product<F: Field + Random, R: rand::Rng + rand::CryptoRng>(
    nv: usize,
    num_multiplicands: usize,
    rng: &mut R,
) -> (Vec<Rc<DenseMultilinearExtension<F>>>, F) {
    let mut multiplicands = Vec::with_capacity(num_multiplicands);
    for _ in 0..num_multiplicands {
        multiplicands.push(Vec::with_capacity(1 << nv));
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();
        for multiplicand in &mut multiplicands {
            let val = F::standard_distribution().sample(rng);
            multiplicand.push(val);
            product *= val;
        }
        sum += product;
    }
    (
        multiplicands
            .into_iter()
            .map(|x| Rc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
            .collect(),
        sum,
    )
}

#[allow(dead_code)]
fn random_list_of_products<F: Field + Random, R: rand::Rng + rand::CryptoRng>(
    nv: usize,
    num_multiplicands_range: (usize, usize),
    num_products: usize,
    rng: &mut R,
) -> (ListOfProductsOfPolynomials<F>, F) {
    let mut sum = F::zero();
    let mut poly = ListOfProductsOfPolynomials::new(nv);
    for _ in 0..num_products {
        let num_multiplicands = num_multiplicands_range.0;
        let (product, product_sum) = random_product(nv, num_multiplicands, rng);
        let coefficient = F::standard_distribution().sample(rng);
        poly.add_product(product.into_iter(), coefficient);
        sum += product_sum * coefficient;
    }
    (poly, sum)
}

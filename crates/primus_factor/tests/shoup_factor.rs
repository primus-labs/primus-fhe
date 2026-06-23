use primus_factor::{
    Factor, FactorMul, FactorSliceOps, LazyFactorMul, LazyFactorSliceOps, ShoupFactor,
};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use rand::{distr::Uniform, prelude::*};

type ValueT = u32;

const MODULUS: ValueT = 536_813_569;

fn ensure_trait<T, F: Factor<T>>(_factor: F) {}

#[test]
fn test_trait_bound() {
    ensure_trait(ShoupFactor::new(1, MODULUS));
}

#[test]
fn scalar_mul_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..256 {
        let factor_value = distr.sample(&mut rng);
        let rhs = distr.sample(&mut rng);
        let factor = ShoupFactor::new(factor_value, MODULUS);

        let expected = modulus.reduce_mul(factor_value, rhs);
        assert_eq!(factor.factor_mul_modulo(rhs, MODULUS), expected);

        let lazy = factor.lazy_factor_mul_modulo(rhs, MODULUS);
        assert!(lazy < MODULUS * 2);
        assert_eq!(modulus.reduce_once(lazy), expected);
    }
}

#[test]
fn reset_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let mut factor = ShoupFactor::new(1, MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..64 {
        let factor_value = distr.sample(&mut rng);
        let rhs = distr.sample(&mut rng);

        factor.set(factor_value, MODULUS);
        assert_eq!(
            factor.factor_mul_modulo(rhs, MODULUS),
            modulus.reduce_mul(factor_value, rhs)
        );

        factor.set_modulus(MODULUS);
        assert_eq!(
            factor.factor_mul_modulo(rhs, MODULUS),
            modulus.reduce_mul(factor_value, rhs)
        );
    }
}

#[test]
fn slice_mul_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 64, 65] {
        let factor_value = distr.sample(&mut rng);
        let factor = ShoupFactor::new(factor_value, MODULUS);
        let input: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let expected: Vec<ValueT> = input
            .iter()
            .map(|&value| modulus.reduce_mul(factor_value, value))
            .collect();

        let mut assign = input.clone();
        factor.factor_mul_slice_assign(&mut assign, MODULUS);
        assert_eq!(assign, expected, "factor_mul_slice_assign len={len}");

        let mut output = vec![0; len];
        factor.factor_mul_slice_to(&input, &mut output, MODULUS);
        assert_eq!(output, expected, "factor_mul_slice_to len={len}");

        let mut lazy_assign = input.clone();
        factor.lazy_factor_mul_slice_assign(&mut lazy_assign, MODULUS);
        for value in &lazy_assign {
            assert!(*value < MODULUS * 2, "lazy assign result >= 2M");
        }
        for value in &mut lazy_assign {
            *value = modulus.reduce_once(*value);
        }
        assert_eq!(
            lazy_assign, expected,
            "lazy_factor_mul_slice_assign len={len}"
        );

        let mut lazy_output = vec![0; len];
        factor.lazy_factor_mul_slice_to(&input, &mut lazy_output, MODULUS);
        for value in &lazy_output {
            assert!(*value < MODULUS * 2, "lazy to result >= 2M");
        }
        for value in &mut lazy_output {
            *value = modulus.reduce_once(*value);
        }
        assert_eq!(lazy_output, expected, "lazy_factor_mul_slice_to len={len}");
    }
}

#[test]
fn fused_slice_ops_against_barrett() {
    let modulus = BarrettModulus::<ValueT>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let factor_value = distr.sample(&mut rng);
        let factor = ShoupFactor::new(factor_value, MODULUS);
        let rhs: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let acc: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let addend: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let products: Vec<ValueT> = rhs
            .iter()
            .map(|&value| modulus.reduce_mul(factor_value, value))
            .collect();

        let expected_add: Vec<ValueT> = acc
            .iter()
            .zip(&products)
            .map(|(&acc, &product)| modulus.reduce_add(acc, product))
            .collect();
        let mut add_assign = acc.clone();
        factor.add_factor_mul_slice_assign(&mut add_assign, &rhs, MODULUS);
        assert_eq!(
            add_assign, expected_add,
            "add_factor_mul_slice_assign len={len}"
        );

        let expected_sub: Vec<ValueT> = acc
            .iter()
            .zip(&products)
            .map(|(&acc, &product)| modulus.reduce_sub(acc, product))
            .collect();
        let mut sub_assign = acc.clone();
        factor.sub_factor_mul_slice_assign(&mut sub_assign, &rhs, MODULUS);
        assert_eq!(
            sub_assign, expected_sub,
            "sub_factor_mul_slice_assign len={len}"
        );

        let expected_to: Vec<ValueT> = products
            .iter()
            .zip(&addend)
            .map(|(&product, &addend)| modulus.reduce_add(product, addend))
            .collect();
        let mut output = vec![0; len];
        factor.factor_mul_add_slice_to(&rhs, &addend, &mut output, MODULUS);
        assert_eq!(output, expected_to, "factor_mul_add_slice_to len={len}");
    }
}

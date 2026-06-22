//! Cross-validation tests for `BarrettModulus`.
//!
//! All basic ops (add/sub/neg/once) are checked against `UintModulus`.

use primus_modulus::{BarrettModulus, UintModulus};
use primus_reduce::{FieldContext, prelude::*};
use rand::{RngExt, distr::Uniform, prelude::*};

type ValueT = u32;

const MODULUS: ValueT = 536_813_569;

#[test]
fn constructor_bounds() {
    assert!(std::panic::catch_unwind(|| BarrettModulus::<ValueT>::new(0)).is_err());
    assert!(std::panic::catch_unwind(|| BarrettModulus::<ValueT>::new(1)).is_err());

    let limit = (1u32) << (ValueT::BITS - 2);
    assert!(BarrettModulus::<ValueT>::try_new(limit - 1).is_some());
    assert!(BarrettModulus::<ValueT>::try_new(limit).is_none());
}

fn field_trait<M: FieldContext<ValueT>>(_modulus: M) {}

#[test]
fn scalar_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();

    field_trait(b);

    let mut rng = rand::rng();

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let c: u32 = distr.sample(&mut rng);

        assert_eq!(b.reduce_add(a, c), u.reduce_add(a, c));
        assert_eq!(b.reduce_sub(a, c), u.reduce_sub(a, c));
        assert_eq!(b.reduce_double(a), u.reduce_double(a));
        assert_eq!(b.reduce_neg(a), u.reduce_neg(a));

        let v = if rng.random_bool(0.5) {
            a
        } else {
            a.wrapping_add(MODULUS)
        };
        assert_eq!(b.reduce_once(v), u.reduce_once(v));

        let product = (a as u64) * (c as u64);
        let expected = (product % MODULUS as u64) as u32;
        assert_eq!(b.reduce((product as u32, (product >> 32) as u32)), expected);
    }
}

#[test]
fn slice_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        for op in &["add", "sub", "neg", "once"] {
            let a_in = match *op {
                "once" => a.iter().map(|&x| x.wrapping_add(MODULUS)).collect(),
                _ => a.clone(),
            };
            let mut b_res = a_in.clone();
            let mut u_res = a_in;

            match *op {
                "add" => {
                    b.reduce_add_slice_assign(&mut b_res, &c);
                    u.reduce_add_slice_assign(&mut u_res, &c);
                }
                "sub" => {
                    b.reduce_sub_slice_assign(&mut b_res, &c);
                    u.reduce_sub_slice_assign(&mut u_res, &c);
                }
                "neg" => {
                    b.reduce_neg_slice_assign(&mut b_res);
                    u.reduce_neg_slice_assign(&mut u_res);
                }
                "once" => {
                    b.reduce_once_slice_assign(&mut b_res);
                    u.reduce_once_slice_assign(&mut u_res);
                }
                _ => {}
            }
            assert_eq!(b_res, u_res, "{op} len={len}");
        }
    }
}

// ===========================================================================
// Barrett-specific mul ops — validated against wide-integer (u64) reference
// ===========================================================================

fn mul_mod(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % MODULUS as u64) as u32
}

#[test]
fn mul_ops() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let b: u32 = distr.sample(&mut rng);
        let d: u32 = distr.sample(&mut rng);

        assert_eq!(m.reduce_mul(a, b), mul_mod(a, b));
        assert_eq!(m.reduce_square(a), mul_mod(a, a));

        let expected_fma = ((a as u64 * b as u64 + d as u64) % MODULUS as u64) as u32;
        assert_eq!(m.reduce_mul_add(a, b, d), expected_fma);

        // lazy_reduce_mul: result in [0, 2M), canonical after reduce_once
        let lazy = m.lazy_reduce_mul(a, b);
        assert!(lazy < MODULUS * 2);
        assert_eq!(m.reduce_once(lazy), mul_mod(a, b));
    }
}

#[test]
fn dot_product() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 7, 15, 16, 17, 31, 32, 33, 127, 128, 129] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let expected = a.iter().zip(&b).fold(0u64, |acc, (&x, &y)| {
            (acc + x as u64 * y as u64) % MODULUS as u64
        }) as u32;
        assert_eq!(
            m.reduce_dot_product(&a, &b),
            expected,
            "dot_product len={len}"
        );
        assert_eq!(
            m.reduce_dot_product_iter(a.iter().copied(), b.iter().copied()),
            expected,
            "dot_product_iter len={len}"
        );
    }
}

#[test]
fn mul_slice_ops() {
    let m = BarrettModulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[0usize, 1, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let scalar: u32 = distr.sample(&mut rng);
        let expected_mul: Vec<u32> = a.iter().zip(&b).map(|(&x, &y)| mul_mod(x, y)).collect();

        // reduce_mul_slice_assign / to
        let mut assign = a.clone();
        m.reduce_mul_slice_assign(&mut assign, &b);
        assert_eq!(assign, expected_mul, "mul_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_mul_slice_to(&a, &b, &mut to);
        assert_eq!(to, expected_mul, "mul_slice_to len={len}");

        // scalar_mul variant
        let expected_scalar: Vec<u32> = a.iter().map(|&x| mul_mod(x, scalar)).collect();
        let mut assign = a.clone();
        m.reduce_mul_scalar_slice_assign(&mut assign, scalar);
        assert_eq!(assign, expected_scalar, "scalar_mul_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_mul_scalar_slice_to(&a, scalar, &mut to);
        assert_eq!(to, expected_scalar, "scalar_mul_slice_to len={len}");

        // lazy_reduce_mul_slice_assign / to
        let mut lazy_assign = a.clone();
        m.lazy_reduce_mul_slice_assign(&mut lazy_assign, &b);
        for v in lazy_assign.iter() {
            assert!(*v < MODULUS * 2, "lazy >= 2M");
        }
        for (v, &exp) in lazy_assign.iter_mut().zip(&expected_mul) {
            *v = m.reduce_once(*v);
            assert_eq!(*v, exp, "lazy_mul_slice_assign len={len}");
        }
        let mut lazy_to = vec![0; len];
        m.lazy_reduce_mul_slice_to(&a, &b, &mut lazy_to);
        for v in lazy_to.iter_mut() {
            assert!(*v < MODULUS * 2);
            *v = m.reduce_once(*v);
        }
        assert_eq!(lazy_to, expected_mul, "lazy_mul_slice_to len={len}");

        // reduce_add_mul_slice_assign: acc += a * b
        let expected_acc: Vec<u32> = c
            .iter()
            .zip(&a)
            .zip(&b)
            .map(|((&acc, &x), &y)| ((acc as u64 + x as u64 * y as u64) % MODULUS as u64) as u32)
            .collect();
        let mut acc = c.clone();
        m.reduce_add_mul_slice_assign(&mut acc, &a, &b);
        assert_eq!(acc, expected_acc, "add_mul_slice_assign len={len}");

        // reduce_sub_mul_slice_assign: acc -= a * b
        let expected_sub: Vec<u32> = c
            .iter()
            .zip(&a)
            .zip(&b)
            .map(|((&acc, &x), &y)| {
                let prod = mul_mod(x, y);
                if acc >= prod {
                    acc - prod
                } else {
                    acc + MODULUS - prod
                }
            })
            .collect();
        let mut acc = c.clone();
        m.reduce_sub_mul_slice_assign(&mut acc, &a, &b);
        assert_eq!(acc, expected_sub, "sub_mul_slice_assign len={len}");

        // reduce_mul_add_slice_to: output = a * b + c
        let expected_abc: Vec<u32> = a
            .iter()
            .zip(&b)
            .zip(&c)
            .map(|((&x, &y), &z)| ((x as u64 * y as u64 + z as u64) % MODULUS as u64) as u32)
            .collect();
        let mut out = vec![0; len];
        m.reduce_mul_add_slice_to(&a, &b, &c, &mut out);
        assert_eq!(out, expected_abc, "mul_add_slice_to len={len}");

        // reduce_scalar_mul_add_slice_to: output = scalar * b + c
        let expected_sbc: Vec<u32> = b
            .iter()
            .zip(&c)
            .map(|(&y, &z)| ((scalar as u64 * y as u64 + z as u64) % MODULUS as u64) as u32)
            .collect();
        let mut out = vec![0; len];
        m.reduce_mul_scalar_add_slice_to(&b, scalar, &c, &mut out);
        assert_eq!(out, expected_sbc, "scalar_mul_add_slice_to len={len}");

        // reduce_add_scalar_mul_slice_assign: acc += scalar * b
        let expected_asc: Vec<u32> = c
            .iter()
            .zip(&b)
            .map(|(&acc, &y)| ((acc as u64 + scalar as u64 * y as u64) % MODULUS as u64) as u32)
            .collect();
        let mut acc = c.clone();
        m.reduce_add_mul_scalar_slice_assign(&mut acc, &b, scalar);
        assert_eq!(acc, expected_asc, "add_scalar_mul_slice_assign len={len}");
    }
}

#[cfg(feature = "simd")]
#[test]
fn simd_slice_ops_against_uint() {
    let b = BarrettModulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[
        0usize, 1, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
    ] {
        let a: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let c: Vec<u32> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        for op in &["add", "sub", "neg"] {
            let mut b_res = a.clone();
            let mut u_res = a.clone();
            match *op {
                "add" => {
                    b.reduce_add_slice_assign(&mut b_res, &c);
                    u.reduce_add_slice_assign(&mut u_res, &c);
                }
                "sub" => {
                    b.reduce_sub_slice_assign(&mut b_res, &c);
                    u.reduce_sub_slice_assign(&mut u_res, &c);
                }
                "neg" => {
                    b.reduce_neg_slice_assign(&mut b_res);
                    u.reduce_neg_slice_assign(&mut u_res);
                }
                _ => {}
            }
            assert_eq!(b_res, u_res, "simd {op} len={len}");
        }
    }
}

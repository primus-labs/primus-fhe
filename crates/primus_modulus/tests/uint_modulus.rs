//! Tests for `UintModulus` — scalar ops, slice ops.

use primus_modulus::UintModulus;
use primus_reduce::prelude::*;
use rand::{RngExt, distr::Uniform, prelude::*};

type ValueT = u32;
type WideT = u64;
const MODULUS: ValueT = 536_813_569;

// type ValueT = u64;
// type WideT = u128;
// const MODULUS: ValueT = 18_446_744_073_709_551_557;

const MODULUS_W: WideT = MODULUS as WideT;

fn wide_add_mod(a: ValueT, b: ValueT) -> ValueT {
    let s = a as WideT + b as WideT;
    if s >= MODULUS_W {
        (s - MODULUS_W) as ValueT
    } else {
        s as ValueT
    }
}
fn wide_sub_mod(a: ValueT, b: ValueT) -> ValueT {
    if a >= b {
        a - b
    } else {
        (a as WideT + MODULUS_W - b as WideT) as ValueT
    }
}
fn wide_neg_mod(v: ValueT) -> ValueT {
    if v == 0 { 0 } else { MODULUS - v }
}
fn wide_once_mod(v: ValueT) -> ValueT {
    if v >= MODULUS { v - MODULUS } else { v }
}

#[test]
fn scalar_ops() {
    let m = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for _ in 0..20 {
        let a: ValueT = distr.sample(&mut rng);
        let b: ValueT = distr.sample(&mut rng);

        let r = wide_add_mod(a, b);
        assert_eq!(m.reduce_add(a, b), r);
        let mut add_assign = a;
        m.reduce_add_assign(&mut add_assign, b);
        assert_eq!(add_assign, r);

        let r = wide_sub_mod(a, b);
        assert_eq!(m.reduce_sub(a, b), r);
        let mut sub_assign = a;
        m.reduce_sub_assign(&mut sub_assign, b);
        assert_eq!(sub_assign, r);

        let v = if rng.random_bool(0.5) {
            a
        } else {
            a.wrapping_add(MODULUS)
        };
        let r = wide_once_mod(v);
        assert_eq!(m.reduce_once(v), r);
        let mut once_assign = v;
        m.reduce_once_assign(&mut once_assign);
        assert_eq!(once_assign, r);

        let r = wide_neg_mod(a);
        assert_eq!(m.reduce_neg(a), r);
        let mut neg_assign = a;
        m.reduce_neg_assign(&mut neg_assign);
        assert_eq!(neg_assign, r);
    }
}

#[test]
fn slice_ops() {
    let m = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = rand::rng();

    for &len in &[
        0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
    ] {
        let a: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();
        let b: Vec<ValueT> = (0..len).map(|_| distr.sample(&mut rng)).collect();

        let once_in: Vec<ValueT> = a
            .iter()
            .map(|&x| {
                if rng.random_bool(0.5) {
                    x
                } else {
                    x.wrapping_add(MODULUS)
                }
            })
            .collect();
        let expected_once: Vec<ValueT> = once_in.iter().copied().map(wide_once_mod).collect();

        let mut assign = once_in.clone();
        m.reduce_once_slice_assign(&mut assign);
        assert_eq!(assign, expected_once, "once_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_once_slice_to(&once_in, &mut to);
        assert_eq!(to, expected_once, "once_slice_to len={len}");

        let expected_neg: Vec<ValueT> = a.iter().copied().map(wide_neg_mod).collect();
        let mut assign = a.clone();
        m.reduce_neg_slice_assign(&mut assign);
        assert_eq!(assign, expected_neg, "neg_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_neg_slice_to(&a, &mut to);
        assert_eq!(to, expected_neg, "neg_slice_to len={len}");

        let expected_add: Vec<ValueT> = std::iter::zip(&a, &b)
            .map(|(&x, &y)| wide_add_mod(x, y))
            .collect();
        let mut assign = a.clone();
        m.reduce_add_slice_assign(&mut assign, &b);
        assert_eq!(assign, expected_add, "add_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_add_slice_to(&a, &b, &mut to);
        assert_eq!(to, expected_add, "add_slice_to len={len}");

        let expected_sub: Vec<ValueT> = std::iter::zip(&a, &b)
            .map(|(&x, &y)| wide_sub_mod(x, y))
            .collect();
        let mut assign = a.clone();
        m.reduce_sub_slice_assign(&mut assign, &b);
        assert_eq!(assign, expected_sub, "sub_slice_assign len={len}");
        let mut to = vec![0; len];
        m.reduce_sub_slice_to(&a, &b, &mut to);
        assert_eq!(to, expected_sub, "sub_slice_to len={len}");

        let mut rev = b.clone();
        m.reduce_sub_slice_rev_assign(&a, &mut rev);
        assert_eq!(rev, expected_sub, "sub_slice_rev_assign len={len}");
    }
}

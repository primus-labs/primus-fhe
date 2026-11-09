//! Cross-validates `UintModulus` scalar and slice operations.

use primus_modulus::UintModulus;
use primus_reduce::prelude::*;
use rand::{RngExt, SeedableRng, distr::Uniform, prelude::*, rngs::StdRng};

type ValueT = u32;
type WideT = u64;
const MODULUS: ValueT = 4_294_967_291;
const SEED: u64 = 0x5549_4e54_4d4f_4431;

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

/// A near-word-limit modulus exercises wrapping arithmetic against widened scalar formulas.
#[test]
fn scalar_ops() {
    let m = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

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
            rng.random_range(MODULUS..=ValueT::MAX)
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

/// Retain one-step reduction and negation; shared add/sub coverage lives in slice_add_sub.rs.
#[test]
fn unary_slices() {
    let m = UintModulus(MODULUS);
    // These loops have no large-length dispatch. Include zero for negation and
    // q/MAX for one-step reduction instead of repeating random interior values.
    for len in [0, 1, 16, 17] {
        let input: Vec<_> = (0..len).map(|i| [0, 1, MODULUS - 1][i % 3]).collect();
        let once_input: Vec<_> = (0..len)
            .map(|i| [0, MODULUS - 1, MODULUS, ValueT::MAX][i % 4])
            .collect();
        let expected_once: Vec<_> = once_input.iter().copied().map(wide_once_mod).collect();

        let mut assign = once_input.clone();
        m.reduce_once_slice_assign(&mut assign);
        assert_eq!(assign, expected_once, "once_slice_assign len={len}");
        let mut output = vec![ValueT::MAX; len];
        m.reduce_once_slice_to(&once_input, &mut output);
        assert_eq!(output, expected_once, "once_slice_to len={len}");

        let expected_neg: Vec<_> = input.iter().copied().map(wide_neg_mod).collect();
        let mut assign = input.clone();
        m.reduce_neg_slice_assign(&mut assign);
        assert_eq!(assign, expected_neg, "neg_slice_assign len={len}");
        output.fill(ValueT::MAX);
        m.reduce_neg_slice_to(&input, &mut output);
        assert_eq!(output, expected_neg, "neg_slice_to len={len}");
    }
}

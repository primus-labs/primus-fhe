//! Cross-validates `PowOf2Modulus` against `UintModulus`.

use primus_modulus::{PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use rand::{
    RngExt, SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

const MODULUS: u32 = 16_777_216; // 2^24
const SEED: u64 = 0x504f_5732_504f_5732;

/// Both constructors require a nontrivial representable power of two.
#[test]
fn constructor_bounds() {
    let modulus = PowOf2Modulus::new(128u8);
    assert_eq!(modulus.value(), 128);
    assert_eq!(modulus.mask(), 127);

    let modulus = PowOf2Modulus::with_mask(127u8);
    assert_eq!(modulus.value(), 128);
    assert_eq!(modulus.mask(), 127);

    for value in [0u8, 1, 3] {
        assert!(std::panic::catch_unwind(|| PowOf2Modulus::new(value)).is_err());
    }
    for mask in [0u8, 2, u8::MAX] {
        assert!(std::panic::catch_unwind(|| PowOf2Modulus::with_mask(mask)).is_err());
    }
}

/// Compare masked scalar arithmetic and one-step reduction with an explicit modulus.
#[test]
fn scalar_ops_against_uint() {
    let p = PowOf2Modulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let b: u32 = distr.sample(&mut rng);

        assert_eq!(p.reduce_add(a, b), u.reduce_add(a, b));
        assert_eq!(p.reduce_sub(a, b), u.reduce_sub(a, b));
        assert_eq!(p.reduce_neg(a), u.reduce_neg(a));
        assert_eq!(p.reduce_double(a), u.reduce_double(a));

        let v = if rng.random_bool(0.5) {
            a
        } else {
            a.wrapping_add(MODULUS)
        };
        assert_eq!(p.reduce_once(v), u.reduce_once(v));
    }
}

/// A widened product checks masking without sharing the implementation's wrapping arithmetic.
#[test]
fn mul_ops() {
    let p = PowOf2Modulus::<u32>::new(MODULUS);
    let distr = Uniform::new(0, MODULUS).unwrap();
    let mut rng = StdRng::seed_from_u64(SEED);

    for _ in 0..20 {
        let a: u32 = distr.sample(&mut rng);
        let b: u32 = distr.sample(&mut rng);

        let expected_mul = ((a as u64 * b as u64) % MODULUS as u64) as u32;
        assert_eq!(p.reduce_mul(a, b), expected_mul);
        assert_eq!(
            p.reduce_square(a),
            ((a as u64 * a as u64) % MODULUS as u64) as u32
        );
    }
}

/// Mask-based negation agrees with explicit modular negation, including zero and a tail.
#[test]
fn negation_slices_against_uint() {
    let p = PowOf2Modulus::<u32>::new(MODULUS);
    let u = UintModulus(MODULUS);
    for len in [0, 1, 17] {
        let mut actual: Vec<_> = (0..len).map(|i| [0, 1, MODULUS - 1][i % 3]).collect();
        let mut expected = actual.clone();
        p.reduce_neg_slice_assign(&mut actual);
        u.reduce_neg_slice_assign(&mut expected);
        assert_eq!(actual, expected, "len={len}");
    }
}

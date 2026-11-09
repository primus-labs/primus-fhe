//! Scaled-quotient multiplication uses three bit shifts with distinct overflow bounds.
use primus_factor::MultiplyFactor;
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Check canonical and lazy results against a full product, including the largest legal modulus.
fn check<const SHIFT: u32>(modulus: u64) {
    let mut rng = StdRng::seed_from_u64(0x4d55_4c46_4143_544f);
    let edges = [0, 1, modulus / 2, modulus - 1];
    let pairs = edges
        .into_iter()
        .flat_map(|a| edges.map(|b| (a, b)))
        .chain((0..16).map(|_| (rng.random_range(0..modulus), rng.random_range(0..modulus))));
    for (a, b) in pairs {
        let factor = MultiplyFactor::new(a, SHIFT, modulus);
        let expected = (u128::from(a) * u128::from(b) % u128::from(modulus)) as u64;
        assert_eq!(
            factor.mul_modulo::<SHIFT>(b, modulus),
            expected,
            "shift={SHIFT}, q={modulus}"
        );
        let lazy = factor.lazy_mul_modulo::<SHIFT>(b, modulus);
        assert!(lazy < 2 * modulus);
        assert_eq!(lazy % modulus, expected);
    }
}

/// Exercise the 32-bit product branch and the two wide-product shifts, with fixed interior samples.
#[test]
fn scaled_quotients_match_wide_products() {
    check::<32>(536_813_569);
    check::<32>((1 << 30) - 1);
    check::<52>(562_949_953_392_641);
    check::<52>((1 << 50) - 1);
    check::<64>(1_152_921_504_606_830_593);
    check::<64>((1 << 62) - 1);
}

/// The debug precondition rejects a modulus too large for the chosen quotient precision.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "must be less than 2^(BIT_SHIFT - 2)")]
fn rejects_large_modulus_for_multiplication() {
    let modulus = (1u64 << 60) + 7;
    let operand = modulus - 1;
    let factor = MultiplyFactor::new(operand, 52, modulus);
    let _ = factor.mul_modulo::<52>(operand, modulus);
}

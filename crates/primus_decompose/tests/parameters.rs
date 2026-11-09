//! Basic decomposition units and modulus-dependent paired bounds.

use primus_decompose::{
    DecompositionBaseLog, DecompositionLevelCount, big_integer::BigUintApproxSignedBasis,
};
use primus_integer::BigUint;

#[test]
fn units_validate_basic_ranges_without_imposing_a_word_width() {
    for log in [0, 1] {
        assert!(DecompositionBaseLog::try_new(log).is_err());
    }
    assert!(DecompositionLevelCount::try_new(0).is_err());
    assert!(DecompositionBaseLog::try_new(u32::MAX).is_ok());
    assert!(DecompositionLevelCount::try_new(usize::MAX).is_ok());

    // A multi-limb modulus legitimately retains more levels than one u32 word.
    let modulus = [0, 0, 0, 1u32];
    let basis = BigUintApproxSignedBasis::new(
        BigUint(&modulus[..]),
        DecompositionBaseLog::new(2),
        Some(DecompositionLevelCount::new(48)),
    );
    assert_eq!(basis.level_count().get(), 48);
    assert_eq!(basis.drop_bits(), 1);
}

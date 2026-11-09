//! Batch helpers require dimensions whose `dimension + 1` fits in `usize`.
//! Parameter and key constructors establish this invariant before use here.

use primus_integer::FheUint;
use primus_lattice::lwe::LweIter;

/// Computes the exact batch storage length, including each ciphertext's body.
/// The batch count needs its own overflow check.
pub(crate) fn batch_len(dimension: usize, count: usize) -> usize {
    (dimension + 1)
        .checked_mul(count)
        .expect("LWE batch storage length overflow")
}

/// Validates the exact operation length before writing or sampling, returning
/// the per-ciphertext length for iteration without silently omitting a tail.
pub(crate) fn check_batch<T>(data: &[T], dimension: usize, count: usize) -> usize {
    assert_eq!(
        data.len(),
        batch_len(dimension, count),
        "LWE batch length mismatch"
    );
    dimension + 1
}

/// Validates an input whose count is inferred from its length before iterating.
pub(crate) fn batch_iter<T: FheUint>(data: &[T], dimension: usize) -> LweIter<'_, T> {
    let lwe_len = dimension + 1;
    assert!(
        data.len().is_multiple_of(lwe_len),
        "incomplete LWE batch ciphertext"
    );
    LweIter::new(data, lwe_len)
}

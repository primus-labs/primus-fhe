//! Private LUT compilers. Encoding and domain/slot capacity are checked before
//! allocation or callbacks. Center collisions and output values are checked
//! while filling the final polynomial directly.

mod front_half;
mod odd_full_domain;

use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_shape::PolyLength;

use crate::LookupTableError;

pub use front_half::front_half_domain_len;
pub(super) use front_half::{
    compile as compile_front_half, compile_to as compile_front_half_to,
    validate as validate_front_half,
};
pub(super) use odd_full_domain::compile as compile_odd_full_domain;

pub(super) fn validate_input_encoding<T: FheUint>(
    poly_length: PolyLength,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: Option<T>,
) -> Result<(), LookupTableError> {
    // PolyLength establishes the ring geometry; the rotation domain must also
    // fit the coefficient word, including for narrow integer implementations.
    T::try_from(2 * poly_length.get()).map_err(|_| LookupTableError::RotationDomainTooLarge)?;
    if input_plaintext_modulus <= T::ONE
        || input_ciphertext_modulus.is_some_and(|q| q <= input_plaintext_modulus)
    {
        return Err(LookupTableError::InvalidInputEncoding);
    }
    Ok(())
}

/// Returns the integer midpoint of `lhs` and `rhs`, rounding upward.
#[inline]
pub(super) fn upper_midpoint(lhs: usize, rhs: usize) -> usize {
    lhs.midpoint(rhs) + ((lhs ^ rhs) & 1)
}

/// Fills the tail with -f(0), reusing the first programmed output group.
/// The prefix contains at least one group; both parts contain whole groups.
#[inline]
pub(super) fn fill_negated_tail<T: FheUint, M: RingContext<T>>(
    output: &mut [T],
    tail_start: usize,
    padded_output_count: usize,
    coefficient_modulus: M,
) {
    let (programmed, tail) = output.split_at_mut(tail_start);
    if tail.is_empty() {
        return;
    }
    for (slot, &first) in tail[..padded_output_count]
        .iter_mut()
        .zip(&programmed[..padded_output_count])
    {
        *slot = coefficient_modulus.reduce_neg(first);
    }
    repeat_output_group(tail, padded_output_count);
}

/// Repeats the initialized first output group through the output slice.
/// `padded_output_count` is nonzero and divides the nonempty output length.
#[inline]
pub(super) fn repeat_output_group<T: Copy>(output: &mut [T], padded_output_count: usize) {
    if padded_output_count == 1 {
        output.fill(output[0]);
    } else {
        // Double the initialized prefix instead of copying each short group.
        let mut filled = padded_output_count;
        while filled < output.len() {
            let (prefix, remaining) = output.split_at_mut(filled);
            let count = remaining.len().min(filled);
            remaining[..count].copy_from_slice(&prefix[..count]);
            filled += count;
        }
    }
}

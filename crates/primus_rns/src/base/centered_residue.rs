use primus_modulus::BarrettModulus;
use primus_reduce::{Reduce, ReduceSub};

use super::small_kernels::slice::wrapping_decompose_chunk_to;

/// Writes centered lifts from one odd modulus as canonical residues in another.
///
/// For source modulus `p`, the integer lift of `r` is `r` through `p/2`
/// and `r-p` above it. Each lift is reduced modulo the target.
///
/// # Panics
/// Panics if the input and output lengths differ.
///
/// # Correctness
/// The source modulus must be positive and odd, and each input must be
/// canonical modulo it. `source_mod_target` must equal the source modulus
/// reduced modulo `target`. Callers can precompute it when preparing a basis.
#[inline]
pub fn lift_centered_residues_to(
    input: &[u64],
    output: &mut [u64],
    source_modulus: u64,
    target: BarrettModulus<u64>,
    source_mod_target: u64,
) {
    // The cold error path needs no operands from this inlined kernel.
    assert!(input.len() == output.len(), "centered lift length mismatch");
    debug_assert_eq!(source_modulus & 1, 1);

    let half = source_modulus / 2;
    if source_modulus < target.value() {
        // Both lifts are already canonical after adding the target to negative ones.
        wrapping_decompose_chunk_to(input, output, half + 1, target.value() - source_modulus);
    } else {
        for (&residue, correction) in input.iter().zip(output) {
            let reduced = target.reduce(residue);
            *correction = if residue > half {
                target.reduce_sub(reduced, source_mod_target)
            } else {
                reduced
            };
        }
    }
}

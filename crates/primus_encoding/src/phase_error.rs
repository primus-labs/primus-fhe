//! Exact circular distances from explicitly expected encoded phases.

use primus_integer::FheUint;
use primus_reduce::ReduceSub;

/// Returns the nonnegative circular distance from `phase` to `expected_phase`.
///
/// Computes `min((phase - expected_phase) mod q, (expected_phase - phase) mod q)`
/// exactly in `T`, without allocation or floating-point conversion. The result
/// lies in `[0, floor(q/2)]`; an exact half-modulus difference returns `q/2`
/// without assigning a sign. Native `q = 2^T::BITS` needs no representable `q`.
///
/// Encode the **expected message** using the actual codec and embedding to
/// obtain `expected_phase`. Re-encoding a decoded message instead measures the
/// residual to that codeword and can hide a decoding failure. This distance
/// cannot recover an integer error that has wrapped around the modulus or
/// distinguish encryption noise from other phase errors.
///
/// # Correctness
///
/// Both inputs must be canonical residues under `modulus`, as required by
/// [`ReduceSub::reduce_sub`]. Every `T` value is canonical for a native modulus.
/// Residue ranges and the choice of reference codec/embedding are not checked.
///
/// # Example
///
/// ```
/// use primus_encoding::{PlaintextEmbedding, RoundedCodec, phase_error_magnitude};
/// use primus_modulus::PowOf2Modulus;
///
/// let modulus = PowOf2Modulus::new(256u64);
/// let codec = RoundedCodec::new(4, modulus);
/// let expected_phase = codec.encode_value(0, PlaintextEmbedding::Unsigned);
/// let phase = 64; // Decodes to 1, although the expected message was 0.
/// assert_eq!(codec.decode_value(phase), 1);
/// assert_eq!(phase_error_magnitude(phase, expected_phase, modulus), 64);
/// ```
#[must_use]
#[inline]
pub fn phase_error_magnitude<T, M>(phase: T, expected_phase: T, modulus: M) -> T
where
    T: FheUint,
    M: Copy + ReduceSub<T, Output = T>,
{
    modulus
        .reduce_sub(phase, expected_phase)
        .min(modulus.reduce_sub(expected_phase, phase))
}

/// Overwrites `output` with the circular distance for each pair of phases.
///
/// Uses [`phase_error_magnitude`] without allocating or modifying the inputs.
/// All three slices must have equal lengths; empty slices are valid. Magnitudes
/// are computed independently under one common modulus, not across RNS limbs.
///
/// # Correctness
///
/// Every pair must satisfy [`phase_error_magnitude`]'s residue and reference
/// requirements. These numerical conditions are not checked.
///
/// # Panics
///
/// Panics before writing if the slice lengths differ. A panicking custom
/// modular subtraction can leave partially written output.
pub fn phase_error_magnitude_slice_to<T, M>(
    phase: &[T],
    expected_phase: &[T],
    output: &mut [T],
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceSub<T, Output = T>,
{
    assert_eq!(
        phase.len(),
        expected_phase.len(),
        "phase and expected phase lengths differ"
    );
    assert_eq!(phase.len(), output.len(), "phase and output lengths differ");

    for ((&phase, &expected_phase), output) in phase.iter().zip(expected_phase).zip(output) {
        *output = phase_error_magnitude(phase, expected_phase, modulus);
    }
}

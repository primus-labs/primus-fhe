//! Packing key switching from an independent LWE secret to a GLWE secret.

use primus_integer::FheUint;
use primus_lwe::LweSecretKeyRef;
use primus_reduce::RingContext;

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::FourierLwePackingKeySwitchingKey;
#[cfg(feature = "ntt")]
pub use ntt::NttLwePackingKeySwitchingKey;

/// Visits secret coefficients in their encoded representation without copying the key.
fn for_each_secret<T: FheUint, M: RingContext<T>>(
    secret: LweSecretKeyRef<'_, T>,
    modulus: M,
    visit: impl FnMut(T),
) {
    match secret {
        LweSecretKeyRef::Encoded(values) => values.iter().copied().for_each(visit),
        LweSecretKeyRef::Signed(values) => values
            .iter()
            .map(|&value| modulus.encode_signed(value))
            .for_each(visit),
    }
}

/// Validates complete LWE blocks and a nonempty batch that fits one output polynomial.
fn check_batch(length: usize, dimension: usize, poly_length: usize) -> usize {
    let lwe_len = dimension + 1;
    assert!(
        length.is_multiple_of(lwe_len),
        "packing input must contain complete LWEs"
    );
    let count = length / lwe_len;
    assert!(
        (1..=poly_length).contains(&count),
        "packing LWE count must be in 1..=N"
    );
    count
}

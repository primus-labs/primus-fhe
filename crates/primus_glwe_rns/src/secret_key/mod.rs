//! DCRT-domain GLWE secret keys.

mod dcrt;

use primus_integer::FheUint;
use primus_modulus::UintModulus;
use primus_reduce::EncodeSigned;

pub use dcrt::{
    DcrtGlevEncryptor, DcrtGlweDecryptWorkspace, DcrtGlweSecretKey, DcrtGlweSecretKeyContext,
};

/// Encodes one signed secret polynomial without scaling or general reduction.
/// Its supported magnitudes are established by parameter/key construction.
fn encode_secret_polynomial_to<T: FheUint>(
    coefficients: &[T::SignedInteger],
    output: &mut [T],
    modulus: T,
) {
    UintModulus(modulus).encode_signed_slice_to(coefficients, output);
}

/// Copies the same signed polynomial into every ordered modulus block.
/// This keeps modulus-major traversal and delegates each bounded lift to reduce.
pub(crate) fn encode_secret_polynomial_to_rns<T: FheUint>(
    coefficients: &[T::SignedInteger],
    output: &mut [T],
    moduli: &[T],
) {
    assert_eq!(output.len(), coefficients.len() * moduli.len());
    output
        .chunks_exact_mut(coefficients.len())
        .zip(moduli)
        .for_each(|(modulus_limb, &modulus)| {
            encode_secret_polynomial_to(coefficients, modulus_limb, modulus);
        });
}

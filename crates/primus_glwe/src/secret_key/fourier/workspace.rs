//! Reusable Fourier decryption workspace.

use primus_poly::FourierPolynomialOwned;
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable Fourier-domain workspace for Fourier GLWE decryption.
pub struct FourierGlweDecryptWorkspace {
    pub(super) phase: FourierPolynomialOwned,
}

impl FourierGlweDecryptWorkspace {
    /// Creates a decryption workspace for coefficient polynomials of length `poly_length`.
    #[inline]
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        let poly_length = poly_length.get();
        Self {
            phase: FourierPolynomialOwned::zero(poly_length / 2),
        }
    }
}

impl Zeroize for FourierGlweDecryptWorkspace {
    #[inline]
    fn zeroize(&mut self) {
        for value in self.phase.as_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
    }
}

impl ZeroizeOnDrop for FourierGlweDecryptWorkspace {}

impl Drop for FourierGlweDecryptWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

//! Reusable secret workspaces.

use primus_fft::Complex64;
use primus_integer::FheUint;
use primus_poly::{FourierPolynomialOwned, PolynomialOwned};
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient buffer for Fourier NTRU encryption.
/// Sensitive coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruEncryptWorkspace<T: FheUint> {
    pub(super) coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierNtruEncryptWorkspace<T> {
    /// Creates an encryption workspace for polynomials of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            coeff: PolynomialOwned::zero(poly_length.get()),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.coeff.as_mut().iter_mut().zeroize();
        self.coeff.0.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruEncryptWorkspace<T> {}

impl<T: FheUint> Drop for FourierNtruEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable Fourier buffer for NTRU phase computation and decryption.
/// Sensitive phase values are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruDecryptWorkspace {
    pub(super) phase: FourierPolynomialOwned,
}

impl FourierNtruDecryptWorkspace {
    /// Creates a decryption workspace for polynomials of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            phase: FourierPolynomialOwned::zero(poly_length.fourier_poly_len()),
        }
    }
}

impl Zeroize for FourierNtruDecryptWorkspace {
    fn zeroize(&mut self) {
        for value in self.phase.as_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.phase.0.spare_capacity_mut().zeroize();
    }
}

impl ZeroizeOnDrop for FourierNtruDecryptWorkspace {}

impl Drop for FourierNtruDecryptWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable buffers for Fourier NLev/NGSW generation.
/// Sensitive message coefficients and transforms are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruGadgetEncryptWorkspace<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
    pub(super) transformed: Vec<Complex64>,
    pub(super) ntru: FourierNtruEncryptWorkspace<T>,
}

impl<T: FheUint> FourierNtruGadgetEncryptWorkspace<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            encoded: PolynomialOwned::zero(poly_length.get()),
            transformed: vec![Complex64::default(); poly_length.fourier_poly_len()],
            ntru: FourierNtruEncryptWorkspace::new(poly_length),
        }
    }

    // Drop leaves the nested encryption workspace to its own destructor;
    // explicit zeroization must also erase that still-live workspace.
    fn zeroize_message_buffers(&mut self) {
        self.encoded.as_mut().iter_mut().zeroize();
        self.encoded.0.spare_capacity_mut().zeroize();
        for value in &mut self.transformed {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.transformed.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> Zeroize for FourierNtruGadgetEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.zeroize_message_buffers();
        self.ntru.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruGadgetEncryptWorkspace<T> {}

impl<T: FheUint> Drop for FourierNtruGadgetEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize_message_buffers();
    }
}

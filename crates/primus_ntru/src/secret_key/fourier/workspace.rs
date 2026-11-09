//! Reusable secret workspaces.

use crate::native::NativeProductWorkspace;
use primus_integer::FheUint;
use primus_poly::{FourierPolynomialOwned, PolynomialOwned};
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient and exact product buffers for Fourier NTRU encryption.
/// Sensitive coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruEncryptWorkspace<T: FheUint> {
    pub(super) coeff: PolynomialOwned<T>,
    pub(super) product: NativeProductWorkspace,
}

impl<T: FheUint> FourierNtruEncryptWorkspace<T> {
    /// Creates an encryption workspace for polynomials of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            coeff: PolynomialOwned::zero(poly_length.get()),
            product: NativeProductWorkspace::new(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.coeff.as_mut().iter_mut().zeroize();
        self.coeff.0.spare_capacity_mut().zeroize();
        self.product.zeroize();
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
/// Sensitive message and product coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruGadgetEncryptWorkspace<T: FheUint> {
    pub(super) ntru: FourierNtruEncryptWorkspace<T>,
}

impl<T: FheUint> FourierNtruGadgetEncryptWorkspace<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            ntru: FourierNtruEncryptWorkspace::new(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruGadgetEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.ntru.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruGadgetEncryptWorkspace<T> {}

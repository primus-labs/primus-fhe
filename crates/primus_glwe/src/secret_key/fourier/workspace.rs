//! Reusable encryption and decryption workspaces.

use primus_fft::Complex64;
use primus_integer::FheUint;
use primus_lattice::GadgetSize;
use primus_poly::{FourierPolynomialOwned, PolynomialOwned};
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient-domain workspace for Fourier GLWE encryption.
pub struct FourierGlweEncryptWorkspace<T: FheUint> {
    pub(super) coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierGlweEncryptWorkspace<T> {
    /// Creates an encryption workspace for coefficient polynomials of length `poly_length`.
    #[inline]
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        let poly_length = poly_length.get();
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }

    fn resize(&mut self, poly_length: PolyLength) {
        let poly_length = poly_length.get();
        if self.coeff.as_ref().len() != poly_length {
            self.coeff.0.resize(poly_length, T::ZERO);
        }
    }

    pub(super) fn assert_poly_length(&self, poly_length: usize) {
        assert_eq!(
            self.coeff.as_ref().len(),
            poly_length,
            "Fourier encryption workspace length mismatch"
        );
    }
}

impl<T: FheUint> Zeroize for FourierGlweEncryptWorkspace<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.coeff.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweEncryptWorkspace<T> {}

impl<T: FheUint> Drop for FourierGlweEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

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

/// Reusable workspace for Fourier GLev/GGSW generation.
///
/// GLev requires only a matching polynomial length. GGSW also requires the
/// configured decomposition level count; use [`Self::resize`] to change it.
pub struct FourierGlweGadgetEncryptWorkspace<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
    pub(super) level_transforms: Vec<Complex64>,
    pub(super) glwe: FourierGlweEncryptWorkspace<T>,
}

impl<T: FheUint> FourierGlweGadgetEncryptWorkspace<T> {
    /// Creates reusable workspace for a checked gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length().get();
        let level_count = size.level_count().get();
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![
                Complex64::default();
                level_count * glwe_size.fourier_poly_len()
            ],
            glwe: FourierGlweEncryptWorkspace::new(glwe_size.poly_length()),
        }
    }

    /// Rebinds this workspace to another checked gadget layout.
    pub fn resize(&mut self, size: GadgetSize) {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length().get();

        self.encoded.0.resize(poly_length, T::ZERO);
        self.level_transforms.resize(
            size.level_count().get() * glwe_size.fourier_poly_len(),
            Complex64::default(),
        );
        self.glwe.resize(glwe_size.poly_length());
    }

    pub(crate) fn assert_glev_compatible(&self, size: GadgetSize) {
        let poly_length = size.glwe_size().poly_length().get();
        assert_eq!(
            self.encoded.as_ref().len(),
            poly_length,
            "gadget polynomial workspace length mismatch"
        );
        self.glwe.assert_poly_length(poly_length);
    }

    pub(crate) fn assert_ggsw_compatible(&self, size: GadgetSize) {
        self.assert_glev_compatible(size);
        assert_eq!(
            self.level_transforms.len(),
            size.level_count().get() * size.glwe_size().fourier_poly_len(),
            "gadget level workspace length mismatch"
        );
    }
}

impl<T: FheUint> Zeroize for FourierGlweGadgetEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().iter_mut().zeroize();
        for value in &mut self.level_transforms {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.glwe.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweGadgetEncryptWorkspace<T> {}

impl<T: FheUint> Drop for FourierGlweGadgetEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

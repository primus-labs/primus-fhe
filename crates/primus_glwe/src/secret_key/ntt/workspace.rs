//! Reusable encryption and decryption workspaces.

use primus_integer::FheUint;
use primus_lattice::GadgetSize;
use primus_poly::PolynomialOwned;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable workspace for NTT GLev/GGSW generation.
///
/// GLev and coefficient-output constant GGSW batches require only a matching
/// polynomial length. NTT-output GGSW also requires the configured decomposition
/// level count; use [`Self::resize`] to change it.
pub struct NttGlweGadgetEncryptWorkspace<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
    pub(super) level_transforms: Vec<T>,
}

impl<T: FheUint> NttGlweGadgetEncryptWorkspace<T> {
    /// Creates reusable workspace for a checked gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        let poly_length = size.glwe_size().poly_length().get();
        let level_count = size.level_count().get();
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![T::ZERO; level_count * poly_length],
        }
    }

    /// Rebinds this workspace to another checked gadget layout.
    pub fn resize(&mut self, size: GadgetSize) {
        let poly_length = size.glwe_size().poly_length().get();
        self.encoded.0.resize(poly_length, T::ZERO);
        self.level_transforms
            .resize(size.level_count().get() * poly_length, T::ZERO);
    }

    pub(crate) fn assert_glev_compatible(&self, size: GadgetSize) {
        assert_eq!(
            self.encoded.as_ref().len(),
            size.glwe_size().poly_length().get(),
            "gadget polynomial workspace length mismatch"
        );
    }

    pub(crate) fn assert_ggsw_compatible(&self, size: GadgetSize) {
        self.assert_glev_compatible(size);
        assert_eq!(
            self.level_transforms.len(),
            size.level_count().get() * size.glwe_size().poly_length().get(),
            "gadget level workspace length mismatch"
        );
    }
}

impl<T: FheUint> Zeroize for NttGlweGadgetEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.encoded.0.zeroize();
        self.level_transforms.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGlweGadgetEncryptWorkspace<T> {}

impl<T: FheUint> Drop for NttGlweGadgetEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

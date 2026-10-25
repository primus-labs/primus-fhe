//! Reusable public-key encryption workspace.

use primus_integer::FheUint;
use primus_shape::PolyLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable ephemeral secret storage for NTT GLWE public-key encryption.
///
/// Each encryption overwrites the polynomial before using it. The workspace
/// may be reused across keys and moduli with the same polynomial length;
/// it owns no parameters or precomputation. Storage is securely erased on drop.
pub struct NttGlwePublicEncryptWorkspace<T: FheUint> {
    pub(super) ephemeral: Vec<T>,
}

impl<T: FheUint> NttGlwePublicEncryptWorkspace<T> {
    /// Allocates one ephemeral polynomial of length `poly_length`.
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        let poly_length = poly_length.get();
        Self {
            ephemeral: vec![T::ZERO; poly_length],
        }
    }
}

impl<T: FheUint> Zeroize for NttGlwePublicEncryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.ephemeral.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGlwePublicEncryptWorkspace<T> {}

impl<T: FheUint> Drop for NttGlwePublicEncryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable ephemeral-key storage owned by a prepared public encryptor.
///
/// Obtain this through its encryptor's workspace accessors. Every encryption
/// overwrites the ephemeral polynomial; its final NTT values remain until the
/// next operation, explicit [`Zeroize::zeroize`], or drop. Erasure preserves
/// shape, length and allocation. Ciphertext outputs are caller-owned and are
/// not erased by this workspace.
pub struct DcrtGlwePublicKeyWorkspace<T: FheUint> {
    size: RnsGlweSize,
    ephemeral: Vec<T>,
}

impl<T: FheUint> DcrtGlwePublicKeyWorkspace<T> {
    pub(super) fn new(size: RnsGlweSize) -> Self {
        Self {
            size,
            ephemeral: vec![T::ZERO; size.rns_poly_len()],
        }
    }

    /// Returns the complete GLWE geometry bound to this workspace.
    #[must_use]
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }

    pub(super) fn assert_size(&self, size: RnsGlweSize) {
        assert_eq!(
            self.size, size,
            "public encryption workspace layout mismatch"
        );
        assert_eq!(
            self.ephemeral.len(),
            size.rns_poly_len(),
            "public encryption ephemeral length mismatch"
        );
    }

    pub(super) fn as_mut_slice(&mut self) -> &mut [T] {
        self.ephemeral.as_mut_slice()
    }
}

impl<T: FheUint> Zeroize for DcrtGlwePublicKeyWorkspace<T> {
    fn zeroize(&mut self) {
        self.ephemeral.iter_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlwePublicKeyWorkspace<T> {}

impl<T: FheUint> Drop for DcrtGlwePublicKeyWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_lattice::{GlweDimension, GlweSize};
    use primus_shape::PolyLength;

    #[test]
    fn explicit_erasure_keeps_workspace_shape_and_allocation() {
        fn check<T: FheUint>() {
            let size =
                RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(32)), 3);
            let mut workspace = DcrtGlwePublicKeyWorkspace::<T>::new(size);
            workspace.ephemeral.fill(T::MAX);
            let pointer = workspace.ephemeral.as_ptr();
            let capacity = workspace.ephemeral.capacity();
            workspace.zeroize();
            workspace.assert_size(size);
            assert!(workspace.ephemeral.iter().all(|&value| value == T::ZERO));
            assert_eq!(workspace.ephemeral.as_ptr(), pointer);
            assert_eq!(workspace.ephemeral.capacity(), capacity);
            // Scratch stays writable and can be overwritten by the next call.
            workspace.ephemeral.fill(T::ONE);
            assert_eq!(workspace.ephemeral.len(), size.rns_poly_len());
        }
        check::<u32>();
        check::<u64>();
    }
}

//! Erasing scratch for DCRT phase recovery and coefficient decoding.

use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_poly::DcrtPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable workspace for DCRT GLWE decryption.
///
/// Decryption overwrites both internal buffers. Their contents are securely
/// erased on drop; explicit [`Zeroize::zeroize`] also preserves the allocations
/// and layout so the workspace can be reused.
pub struct DcrtGlweDecryptWorkspace<T: FheUint> {
    size: RnsGlweSize,
    msg_mod_q: DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: Vec<T>,
}

impl<T: FheUint> Zeroize for DcrtGlweDecryptWorkspace<T> {
    fn zeroize(&mut self) {
        self.msg_mod_q.as_mut().iter_mut().zeroize();
        self.fast_convert_buffer.iter_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweDecryptWorkspace<T> {}

impl<T: FheUint> Drop for DcrtGlweDecryptWorkspace<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> DcrtGlweDecryptWorkspace<T> {
    /// Creates a new [`DcrtGlweDecryptWorkspace<T>`].
    #[inline]
    #[must_use]
    pub fn new(size: RnsGlweSize) -> Self {
        let msg_mod_q: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(size.rns_poly_len());
        // The codec's one-modulus converter borrows the phase directly.
        let conversion_len = if size.moduli_count() == 1 {
            0
        } else {
            size.rns_poly_len()
        };
        let fast_convert_buffer = vec![T::ZERO; conversion_len];

        Self {
            size,
            msg_mod_q,
            fast_convert_buffer,
        }
    }

    #[inline]
    pub(super) fn as_mut(&mut self) -> (&mut DcrtPolynomial<Vec<T>>, &mut [T]) {
        (&mut self.msg_mod_q, &mut self.fast_convert_buffer)
    }

    /// Returns the RNS GLWE layout bound to this workspace.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_lattice::GlweDimension;
    use primus_lattice::GlweSize;
    use primus_shape::PolyLength;

    #[test]
    fn decrypt_workspace_erases_both_buffers_without_changing_layout() {
        for count in [1, 2] {
            let size = RnsGlweSize::new(
                GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                count,
            );
            let mut workspace = DcrtGlweDecryptWorkspace::<u64>::new(size);
            workspace.msg_mod_q.as_mut().fill(0xfeed);
            workspace.fast_convert_buffer.fill(0xbeef);
            let phase_ptr = workspace.msg_mod_q.as_ref().as_ptr();
            let conversion_ptr = workspace.fast_convert_buffer.as_ptr();
            let conversion_len = workspace.fast_convert_buffer.len();
            workspace.zeroize();
            assert_eq!(workspace.size(), size);
            assert_eq!(workspace.msg_mod_q.as_ref(), vec![0; size.rns_poly_len()]);
            assert_eq!(workspace.fast_convert_buffer, vec![0; conversion_len]);
            assert_eq!(workspace.msg_mod_q.as_ref().as_ptr(), phase_ptr);
            assert_eq!(workspace.fast_convert_buffer.as_ptr(), conversion_ptr);
        }
    }
}

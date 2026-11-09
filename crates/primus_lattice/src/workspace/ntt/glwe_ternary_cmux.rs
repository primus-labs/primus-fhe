//! NTT scratch storage for ternary GLWE CMux.

use primus_integer::FheUint;

use crate::GadgetSize;
use crate::ggsw::NttGgsw;

use super::NttGlweExternalProductWorkspace;

/// Fixed-layout scratch for [`NttGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined GGSW, one length-`N` monomial NTT vector, and an
/// external-product workspace. The output GLWE supplies the coefficient-domain
/// difference buffer. See the operation's modulus and representation requirements.
pub struct NttGlweTernaryCmuxWorkspace<T: FheUint> {
    pub(crate) combined_control: NttGgsw<Box<[T]>>,
    /// NTT of `-X^-exponent`, shared by every polynomial of the negative control.
    pub(crate) control_factor_ntt: Box<[T]>,
    pub(crate) external_product: NttGlweExternalProductWorkspace<T>,
}

impl<T: FheUint> NttGlweTernaryCmuxWorkspace<T> {
    /// Allocates all buffers for the given gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        Self {
            combined_control: NttGgsw::zero(size.ggsw_len()),
            control_factor_ntt: vec![T::ZERO; size.glwe_size().poly_length().get()]
                .into_boxed_slice(),
            external_product: NttGlweExternalProductWorkspace::new(size),
        }
    }

    /// Reuses external-product buffers between ternary rotations at another
    /// decomposition depth, restoring the control layout even on unwind.
    /// The combined-control allocation retains its original BR basis.
    ///
    /// # Panics
    /// Panics before the operation if `size` changes the GLWE layout.
    pub fn with_external_product<R>(
        &mut self,
        size: GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}

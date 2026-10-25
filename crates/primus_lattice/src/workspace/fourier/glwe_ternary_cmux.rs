//! Fourier scratch storage for ternary GLWE CMux.

use primus_fft::{Complex64, TorusFftValue};

use crate::GadgetSize;
use crate::ggsw::FourierGgsw;

use super::FourierGlweExternalProductWorkspace;

/// Fixed-layout scratch for [`FourierGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined Fourier GGSW, one length-`N/2` integer-scale monomial
/// transform, and an external-product workspace whose digit buffer first holds
/// the coefficient monomial. The output GLWE supplies the difference buffer.
/// Does not bind an FFT table; see the operation's representation requirements.
pub struct FourierGlweTernaryCmuxWorkspace<T: TorusFftValue> {
    pub(crate) combined_control: FourierGgsw<Box<[Complex64]>>,
    pub(crate) control_factor_fourier: Box<[Complex64]>,
    pub(crate) external_product: FourierGlweExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> FourierGlweTernaryCmuxWorkspace<T> {
    /// Allocates all buffers for the given gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        Self {
            combined_control: FourierGgsw::zero(size.fourier_ggsw_len()),
            control_factor_fourier: vec![Complex64::default(); size.glwe_size().fourier_poly_len()]
                .into_boxed_slice(),
            external_product: FourierGlweExternalProductWorkspace::new(size),
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
        operation: impl FnOnce(&mut FourierGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}

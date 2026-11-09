//! Fourier scratch storage for GLWE external products.

use aligned_vec::{AVec, avec};
use primus_data::DataMut;
use primus_fft::{Complex64, TorusFftValue};

use crate::GadgetSize;
use crate::glwe::FourierGlwe;

/// Pre-allocated scratch buffers for a native-torus Fourier external product.
/// Owned Fourier buffers use cache-line alignment for repeated FFT and product passes.
///
/// # Correctness
///
/// Construction and resizing maintain scratch lengths for the bound GLWE size.
/// The bound [`GadgetSize`] also records the decomposition length. This workspace
/// does not bind a basis or FFT table: callers must provide a native-torus basis
/// with matching levels, matching ciphertext layouts, and Fourier data produced
/// with a compatible FFT layout and polynomial length.
///
/// Overwriting products initialize the accumulator; internal accumulating
/// products require an initialized accumulator. Other scratch is written before
/// use, so callers do not need to reset the workspace between operations.
pub struct FourierGlweExternalProductWorkspace<T: TorusFftValue> {
    size: GadgetSize,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// Decomposed (signed) digits for one polynomial (length = `poly_length`).
    pub(crate) decomposed_poly: Vec<T>,
    /// FFT of the decomposed polynomial (length = `fourier_length`).
    pub(crate) decomposed_fourier: AVec<Complex64>,
    /// Accumulator in Fourier domain.
    pub(crate) fourier_accumulator: FourierGlwe<AVec<Complex64>>,
}

/// Mutable view of the buffers used by a Fourier external product.
///
/// The accumulator may borrow either the workspace-owned buffer or a
/// caller-provided Fourier GLWE output.
pub(crate) struct FourierGlweExternalProductWorkspaceRefMut<'a, T: TorusFftValue> {
    size: GadgetSize,
    /// Carry bits used by decomposition.
    pub(crate) carries: &'a mut [bool],
    /// Integer digits and their Fourier transform.
    pub(crate) decomposed_poly: &'a mut [T],
    pub(crate) decomposed_fourier: &'a mut [Complex64],
    /// Accumulator selected for this external product.
    pub(crate) fourier_accumulator: FourierGlwe<&'a mut [Complex64]>,
}

impl<T: TorusFftValue> FourierGlweExternalProductWorkspaceRefMut<'_, T> {
    /// Returns the external-product layout bound to this view.
    #[must_use]
    #[inline]
    pub(crate) fn size(&self) -> GadgetSize {
        self.size
    }
}

impl<T: TorusFftValue> FourierGlweExternalProductWorkspace<T> {
    /// Creates a new workspace with all buffers pre-allocated.
    ///
    /// The accumulator is sized for all mask polynomials and the body.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length().get();
        let fourier_length = glwe_size.fourier_poly_len();

        Self {
            size,
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: avec![Complex64::default(); fourier_length],
            fourier_accumulator: FourierGlwe(avec![
                Complex64::default();
                glwe_size.fourier_glwe_len()
            ]),
        }
    }

    /// Temporarily uses another decomposition depth for a serial operation.
    /// Restores the original layout on return or unwind; no allocation occurs
    /// unless the operation itself replaces or resizes the workspace.
    ///
    /// # Panics
    /// Panics before invoking the operation if the GLWE layout changes.
    pub fn with_rebound<R>(
        &mut self,
        size: GadgetSize,
        operation: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let original = self.size();
        self.rebind(size);
        struct Restore<'a, T: TorusFftValue> {
            workspace: &'a mut FourierGlweExternalProductWorkspace<T>,
            size: GadgetSize,
        }
        impl<T: TorusFftValue> Drop for Restore<'_, T> {
            fn drop(&mut self) {
                self.workspace.resize(self.size);
            }
        }
        let restore = Restore {
            workspace: self,
            size: original,
        };
        operation(&mut *restore.workspace)
    }

    /// Rebinds the workspace to another decomposition layout without reallocating.
    ///
    /// # Panics
    ///
    /// Panics if `size` has a different GLWE dimension or polynomial length.
    fn rebind(&mut self, size: GadgetSize) {
        assert_eq!(
            self.size.glwe_size(),
            size.glwe_size(),
            "cannot rebind Fourier external-product workspace to a different GLWE layout"
        );
        self.size = size;
    }

    /// Rebinds the workspace and resizes its scratch buffers when the GLWE layout changes.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.size.glwe_size() == size.glwe_size() {
            self.size = size;
            return;
        }

        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length().get();
        let fourier_length = glwe_size.fourier_poly_len();

        self.size = size;
        self.carries.resize(poly_length, false);
        self.decomposed_poly.resize(poly_length, T::ZERO);
        self.decomposed_fourier
            .resize(fourier_length, Complex64::default());
        self.fourier_accumulator
            .0
            .resize(glwe_size.fourier_glwe_len(), Complex64::default());
    }

    /// Returns the bound external-product layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Borrows all scratch buffers and the workspace-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> FourierGlweExternalProductWorkspaceRefMut<'_, T> {
        FourierGlweExternalProductWorkspaceRefMut {
            size: self.size,
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierGlwe(self.fourier_accumulator.as_mut()),
        }
    }

    /// Borrows the scratch buffers while using `accumulator` as the output.
    /// The operation entry point must ensure its length matches the bound GLWE size.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut FourierGlwe<S>,
    ) -> FourierGlweExternalProductWorkspaceRefMut<'a, T>
    where
        S: DataMut<Elem = Complex64>,
    {
        FourierGlweExternalProductWorkspaceRefMut {
            size: self.size,
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierGlwe(accumulator.as_mut()),
        }
    }
}

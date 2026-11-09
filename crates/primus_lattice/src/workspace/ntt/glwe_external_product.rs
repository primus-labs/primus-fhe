//! NTT scratch storage for GLWE external products.

use aligned_vec::{AVec, avec};
use primus_data::DataMut;
use primus_integer::FheUint;

use crate::GadgetSize;
use crate::glwe::NttGlwe;

/// Pre-allocated scratch buffers for an NTT external product.
/// Owned coefficient and NTT buffers use cache-line alignment.
///
/// # Correctness
///
/// Construction and resizing maintain scratch lengths for the bound GLWE size.
/// The bound [`GadgetSize`] also records the decomposition length. This workspace
/// does not bind a basis, NTT table, or modulus. Callers must provide matching
/// polynomial lengths, decomposition levels, ciphertext layouts, and the same
/// modulus for the basis, NTT table, and modular arithmetic.
///
/// Overwriting products initialize the accumulator; internal accumulating
/// products require an initialized accumulator. Other scratch is written before
/// use, so callers do not need to reset the workspace between operations.
pub struct NttGlweExternalProductWorkspace<T: FheUint> {
    size: GadgetSize,
    /// Adjusted coefficients used by decomposition (length = `poly_length`).
    pub(crate) adjusted_poly: AVec<T>,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// One decomposed polynomial, transformed in place to NTT form.
    pub(crate) decomposed_ntt: AVec<T>,
    /// Accumulator in NTT form.
    pub(crate) ntt_accumulator: NttGlwe<AVec<T>>,
}

/// Mutable view of the buffers used by an NTT external product.
///
/// The accumulator may borrow either the workspace-owned buffer or a
/// caller-provided NTT GLWE output.
pub(crate) struct NttGlweExternalProductWorkspaceRefMut<'a, T: FheUint> {
    size: GadgetSize,
    /// Adjusted coefficients used by decomposition.
    pub(crate) adjusted_poly: &'a mut [T],
    /// Carry bits used by decomposition.
    pub(crate) carries: &'a mut [bool],
    /// One decomposed polynomial, transformed in place to NTT form.
    pub(crate) decomposed_ntt: &'a mut [T],
    /// Accumulator selected for this external product.
    pub(crate) ntt_accumulator: NttGlwe<&'a mut [T]>,
}

impl<T: FheUint> NttGlweExternalProductWorkspaceRefMut<'_, T> {
    /// Returns the external-product layout bound to this view.
    #[must_use]
    #[inline]
    pub(crate) fn size(&self) -> GadgetSize {
        self.size
    }
}

impl<T: FheUint> NttGlweExternalProductWorkspace<T> {
    /// Creates a workspace with all buffers pre-allocated.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length().get();

        Self {
            size,
            adjusted_poly: avec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: avec![T::ZERO; poly_length],
            ntt_accumulator: NttGlwe(avec![T::ZERO; glwe_size.glwe_len()]),
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
        struct Restore<'a, T: FheUint> {
            workspace: &'a mut NttGlweExternalProductWorkspace<T>,
            size: GadgetSize,
        }
        impl<T: FheUint> Drop for Restore<'_, T> {
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
            "cannot rebind NTT external-product workspace to a different GLWE layout"
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

        self.size = size;
        self.adjusted_poly.resize(poly_length, T::ZERO);
        self.carries.resize(poly_length, false);
        self.decomposed_ntt.resize(poly_length, T::ZERO);
        self.ntt_accumulator.0.resize(glwe_size.glwe_len(), T::ZERO);
    }

    /// Returns the bound external-product layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Borrows all scratch buffers and the workspace-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> NttGlweExternalProductWorkspaceRefMut<'_, T> {
        NttGlweExternalProductWorkspaceRefMut {
            size: self.size,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttGlwe(self.ntt_accumulator.as_mut()),
        }
    }

    /// Borrows the scratch buffers while using `accumulator` as the output.
    /// The operation entry point must ensure its length matches the bound GLWE size.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut NttGlwe<S>,
    ) -> NttGlweExternalProductWorkspaceRefMut<'a, T>
    where
        S: DataMut<Elem = T>,
    {
        NttGlweExternalProductWorkspaceRefMut {
            size: self.size,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttGlwe(accumulator.as_mut()),
        }
    }
}

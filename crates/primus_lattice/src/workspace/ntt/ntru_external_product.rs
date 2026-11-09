//! NTT scratch storage for NTRU external products.

use aligned_vec::{ABox, avec};
use primus_data::DataMut;
use primus_integer::FheUint;
use primus_shape::PolyLength;

use crate::ntru::NttNtru;

/// Pre-allocated scratch buffers for exact NTT NTRU gadget products.
/// Owned coefficient and NTT buffers use cache-line alignment.
///
/// Shared by NLev key switching and NGSW external products, including CMUX.
///
/// # Correctness
///
/// Scratch lengths are fixed by `poly_length`; decomposition levels are not
/// bound, so the workspace can be reused across different decomposition lengths.
/// Callers must supply compatible input and gadget layouts and matching transform
/// lengths. The basis and transform table are not stored in this workspace.
///
/// Overwriting products initialize the accumulator; internal accumulating
/// products require an initialized accumulator. Other scratch is written before
/// use, and no manual reset is needed between operations.
/// The basis, NTT table, and modular arithmetic must use the same modulus.
pub struct NttNtruExternalProductWorkspace<T: FheUint> {
    poly_length: PolyLength,
    /// Modulus-adjusted coefficients reused as decomposition input.
    adjusted_poly: ABox<[T]>,
    /// Carry bits reused while decomposing `adjusted_poly`.
    carries: Box<[bool]>,
    /// Digits for one decomposition level, transformed in place to NTT form.
    decomposed_ntt: ABox<[T]>,
    /// Transform-domain sum of the current external products.
    ntt_accumulator: NttNtru<ABox<[T]>>,
}

/// Mutable view selecting either the workspace-owned or caller-provided NTT accumulator.
/// Decomposition scratch remains borrowed from the owning workspace.
pub(crate) struct NttNtruExternalProductWorkspaceRefMut<'a, T: FheUint> {
    poly_length: usize,
    pub(crate) adjusted_poly: &'a mut [T],
    pub(crate) carries: &'a mut [bool],
    pub(crate) decomposed_ntt: &'a mut [T],
    pub(crate) ntt_accumulator: NttNtru<&'a mut [T]>,
}

impl<T: FheUint> NttNtruExternalProductWorkspaceRefMut<'_, T> {
    #[must_use]
    #[inline]
    pub(crate) fn poly_length(&self) -> usize {
        self.poly_length
    }
}

impl<T: FheUint> NttNtruExternalProductWorkspace<T> {
    /// Creates reusable buffers for NTRU polynomials of length `poly_length`.
    ///
    /// # Correctness
    ///
    /// The transform table used by subsequent operations must support
    /// `poly_length`. Construction does not bind or validate a table;
    /// [`PolyLength`] already establishes the supported FHE geometry.
    #[inline]
    #[must_use]
    pub fn new(poly_length: PolyLength) -> Self {
        Self {
            poly_length,
            adjusted_poly: avec![T::ZERO; poly_length.get()].into_boxed_slice(),
            carries: vec![false; poly_length.get()].into_boxed_slice(),
            decomposed_ntt: avec![T::ZERO; poly_length.get()].into_boxed_slice(),
            ntt_accumulator: NttNtru(avec![T::ZERO; poly_length.get()].into_boxed_slice()),
        }
    }

    /// Returns the coefficient polynomial length bound to this workspace.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Borrows decomposition scratch and the workspace-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> NttNtruExternalProductWorkspaceRefMut<'_, T> {
        NttNtruExternalProductWorkspaceRefMut {
            poly_length: self.poly_length.get(),
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttNtru(self.ntt_accumulator.as_mut()),
        }
    }

    /// Borrows scratch while accumulating directly into `accumulator`.
    /// The operation boundary must establish the output's transform length.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut NttNtru<S>,
    ) -> NttNtruExternalProductWorkspaceRefMut<'a, T>
    where
        S: DataMut<Elem = T>,
    {
        NttNtruExternalProductWorkspaceRefMut {
            poly_length: self.poly_length.get(),
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttNtru(accumulator.as_mut()),
        }
    }
}

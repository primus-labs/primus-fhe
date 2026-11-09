//! Fourier scratch storage for NTRU external products.

use aligned_vec::{ABox, avec};
use primus_data::DataMut;
use primus_fft::{Complex64, TorusFftValue};
use primus_shape::PolyLength;

use crate::ntru::FourierNtru;

/// Pre-allocated scratch buffers for native-torus Fourier NTRU gadget products.
/// Owned Fourier buffers use cache-line alignment for repeated FFT and product passes.
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
/// Fourier data must use a compatible FFT layout, and the basis must use the
/// implicit native-torus modulus.
pub struct FourierNtruExternalProductWorkspace<T: TorusFftValue> {
    poly_length: PolyLength,
    /// Carry bits reused while decomposing one coefficient polynomial.
    carries: Box<[bool]>,
    /// Coefficient-domain digits produced for one decomposition level.
    decomposed_poly: Box<[T]>,
    /// Fourier transform of `decomposed_poly`.
    decomposed_fourier: ABox<[Complex64]>,
    /// Transform-domain sum of the current external products.
    fourier_accumulator: FourierNtru<ABox<[Complex64]>>,
}

/// Mutable view selecting either the workspace-owned or caller-provided Fourier accumulator.
/// Decomposition scratch remains borrowed from the owning workspace.
pub(crate) struct FourierNtruExternalProductWorkspaceRefMut<'a, T: TorusFftValue> {
    poly_length: usize,
    pub(crate) carries: &'a mut [bool],
    pub(crate) decomposed_poly: &'a mut [T],
    pub(crate) decomposed_fourier: &'a mut [Complex64],
    pub(crate) fourier_accumulator: FourierNtru<&'a mut [Complex64]>,
}

impl<T: TorusFftValue> FourierNtruExternalProductWorkspaceRefMut<'_, T> {
    #[must_use]
    #[inline]
    pub(crate) fn poly_length(&self) -> usize {
        self.poly_length
    }
}

impl<T: TorusFftValue> FourierNtruExternalProductWorkspace<T> {
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
        let fourier_length = poly_length.fourier_poly_len();
        Self {
            poly_length,
            carries: vec![false; poly_length.get()].into_boxed_slice(),
            decomposed_poly: vec![T::ZERO; poly_length.get()].into_boxed_slice(),
            decomposed_fourier: avec![Complex64::default(); fourier_length].into_boxed_slice(),
            fourier_accumulator: FourierNtru(
                avec![Complex64::default(); fourier_length].into_boxed_slice(),
            ),
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
    pub(crate) fn as_mut(&mut self) -> FourierNtruExternalProductWorkspaceRefMut<'_, T> {
        FourierNtruExternalProductWorkspaceRefMut {
            poly_length: self.poly_length.get(),
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierNtru(self.fourier_accumulator.as_mut()),
        }
    }

    /// Borrows scratch while accumulating directly into `accumulator`.
    /// The operation boundary must establish the output's transform length.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut FourierNtru<S>,
    ) -> FourierNtruExternalProductWorkspaceRefMut<'a, T>
    where
        S: DataMut<Elem = Complex64>,
    {
        FourierNtruExternalProductWorkspaceRefMut {
            poly_length: self.poly_length.get(),
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierNtru(accumulator.as_mut()),
        }
    }
}

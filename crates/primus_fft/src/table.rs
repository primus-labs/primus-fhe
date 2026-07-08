use num_complex::Complex64;

use crate::error::FftError;
use crate::torus::TorusFftValue;

/// Abstract interface for torus negacyclic FFT tables.
///
/// Implementations provide forward and inverse negacyclic transforms for
/// polynomial multiplication in `Z[X] / (X^N + 1)`.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync` so tables can be shared across
/// threads (read-only) without additional synchronization.
pub trait FftTable: Send + Sync {
    /// Create a new FFT table for the negacyclic transform of size `N = 2^log_n`.
    fn new(log_n: u32) -> Result<Self, FftError>
    where
        Self: Sized;

    /// The polynomial length `N`.
    fn poly_length(&self) -> usize;

    /// The length of the Fourier representation.
    ///
    /// The relationship between `poly_length` and `fourier_length` depends on
    /// the backend:
    ///
    /// - [`FullComplex64FftTable`] stores the full `N` complex values
    ///   (`fourier_length == poly_length`). This is the reference backend.
    /// - A future packed backend will exploit real-input symmetry to store only
    ///   `N / 2` complex values (`fourier_length == poly_length / 2`).
    ///
    /// Callers must always allocate Fourier buffers using this value, never
    /// derive it from `poly_length` directly.
    fn fourier_length(&self) -> usize;

    /// Forward negacyclic transform: torus coefficients → Fourier domain.
    ///
    /// `input` must have length [`poly_length()`](FftTable::poly_length).
    /// `output` receives [`fourier_length()`](FftTable::fourier_length) complex
    /// values.
    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]);

    /// Inverse negacyclic transform: Fourier domain → torus coefficients.
    ///
    /// `input` must have length [`fourier_length()`](FftTable::fourier_length).
    /// `output` receives [`poly_length()`](FftTable::poly_length) torus values.
    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[Complex64], output: &mut [T]);
}

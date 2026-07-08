use num_complex::Complex64;
use primus_fft::TorusFftValue;

/// Pre-allocated scratch buffers for the TFHE external product.
///
/// All allocations happen at construction time.  The hot loop only
/// mutates slices obtained directly from the public fields.
///
/// # GLWE dimension convention
///
/// `glwe_dimension` is the count of *mask* polynomials (`k`).  The
/// accumulator is sized for `glwe_dimension + 1` polynomials (k mask
/// + 1 body), matching the convention of [`Lwe::dimension()`].
///
/// # Design note
///
/// For power-of-two modulus (the common TFHE case), `init_value_carry_slice_to`
/// would just copy the input into a temporary buffer before decomposition.
/// We avoid that waste by reading directly from the input GLWE and using
/// `ApproxSignedBasis::init_carry_slice` (only extracts carries, no copy).
pub struct TfheFftContext<T: TorusFftValue> {
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub carries: Vec<bool>,
    /// Decomposed (signed) digits for one polynomial (length = `poly_length`).
    pub decomposed_poly: Vec<T>,
    /// FFT of the decomposed polynomial (length = `fourier_length`).
    pub decomposed_fourier: Vec<Complex64>,
    /// Accumulator in Fourier domain
    /// (length = `(glwe_dimension + 1) * fourier_length`).
    pub fourier_accumulator: Vec<Complex64>,
}

impl<T: TorusFftValue> TfheFftContext<T> {
    /// Creates a new context with all buffers pre-allocated.
    ///
    /// `glwe_dimension` is the mask count `k`; the accumulator is sized for
    /// `k + 1` polynomials.
    pub fn new(poly_length: usize, fourier_length: usize, glwe_dimension: usize) -> Self {
        let total_polys = glwe_dimension + 1;
        Self {
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: vec![Complex64::new(0.0, 0.0); fourier_length],
            fourier_accumulator: vec![Complex64::new(0.0, 0.0); total_polys * fourier_length],
        }
    }

    /// Resizes all buffers to the given dimensions.
    pub fn resize(&mut self, poly_length: usize, fourier_length: usize, glwe_dimension: usize) {
        let total_polys = glwe_dimension + 1;
        self.carries.resize(poly_length, false);
        self.decomposed_poly.resize(poly_length, T::ZERO);
        self.decomposed_fourier
            .resize(fourier_length, Complex64::new(0.0, 0.0));
        self.fourier_accumulator
            .resize(total_polys * fourier_length, Complex64::new(0.0, 0.0));
    }
}

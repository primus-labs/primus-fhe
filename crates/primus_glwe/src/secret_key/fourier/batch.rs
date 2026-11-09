//! Constant GGSW batches share prepared exact products, never row randomness.

use super::FourierGlweEncryptor;
use crate::GlevParameters;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::ggsw::GgswIterMut;
use primus_modulus::NativeModulus;

impl<T: TorusFftValue> FourierGlweEncryptor<'_, T> {
    /// Encrypts native-ring constants into `[input][row][level][component]`
    /// Fourier GGSWs. Uses independent noise/masks for every row, no plaintext
    /// codec or independent diagonal spectra, and no per-call allocation.
    /// Empty input/output consumes no randomness after resource validation.
    ///
    /// # Panics
    /// Parameter/FFT/output checks precede sampling/writes; batch overflow also
    /// panics. RNG/FFT failures may leave partial output and modified scratch.
    pub fn encrypt_ggsw_constant_batch_to<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &mut self,
        input: &[T],
        output: &mut [Complex64],
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_gadget_compatible(params, fft);
        let len = params.fourier_ggsw_len();
        assert_eq!(
            output.len(),
            input
                .len()
                .checked_mul(len)
                .expect("Fourier GGSW batch length overflow"),
            "Fourier GGSW batch output layout mismatch"
        );
        for (&constant, mut ggsw) in input
            .iter()
            .zip(primus_lattice::ggsw::FourierGgswIterMut::new(output, len))
        {
            for (diagonal, mut glev) in ggsw.iter_glev_mut(params.fourier_glev_len()).enumerate() {
                for (scalar, row) in params
                    .basis()
                    .scalar_iter()
                    .zip(glev.iter_glwe_mut(params.fourier_glwe_len()))
                {
                    self.sample_constant_row(constant, scalar, diagonal, params, rng);
                    self.write_fourier_row(row, fft);
                }
            }
        }
    }

    /// Encrypts constants directly to native coefficient GGSWs in
    /// `[input][row][level][component][coefficient]` order. Uses the same sampled
    /// exact rows as Fourier output, with no FFT, inverse rounding or extra scratch.
    /// No allocation occurs. Empty input/output consumes no randomness.
    ///
    /// # Panics
    /// Parameter/output checks precede sampling/writes; batch overflow also
    /// panics. RNG failures may leave completed rows in output and modified scratch.
    pub fn encrypt_ggsw_constant_batch_coeff_to<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        input: &[T],
        output: &mut [T],
        params: &GlevParameters<T, NativeModulus<T>>,
        rng: &mut R,
    ) {
        assert_eq!(
            self.glwe_size(),
            params.glwe_size(),
            "GLWE parameter layout mismatch"
        );
        let len = params.ggsw_len();
        assert_eq!(
            output.len(),
            input
                .len()
                .checked_mul(len)
                .expect("coefficient GGSW batch length overflow"),
            "coefficient GGSW batch output layout mismatch"
        );
        for (&constant, mut ggsw) in input.iter().zip(GgswIterMut::new(output, len)) {
            for (diagonal, mut glev) in ggsw.iter_glev_mut(params.glev_len()).enumerate() {
                for (scalar, mut row) in params
                    .basis()
                    .scalar_iter()
                    .zip(glev.iter_glwe_mut(params.glwe_len()))
                {
                    self.sample_constant_row(constant, scalar, diagonal, params, rng);
                    row.as_mut().copy_from_slice(&self.row);
                }
            }
        }
    }

    /// Only the constant diagonal changes; all other coefficients retain their
    /// sampled values. The body has already used the original, unmodified masks.
    fn sample_constant_row<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        constant: T,
        scalar: T,
        diagonal: usize,
        params: &GlevParameters<T, NativeModulus<T>>,
        rng: &mut R,
    ) {
        self.sample_gadget_row(
            diagonal,
            params.encryption_parameters(),
            rng,
            |coefficients| {
                coefficients[0] = coefficients[0].wrapping_add(constant.wrapping_mul(scalar));
            },
        );
    }
}

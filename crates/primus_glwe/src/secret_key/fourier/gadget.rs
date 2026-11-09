//! Gadget scaling and native diagonals precede every Fourier conversion.

use super::FourierGlweEncryptor;
use crate::{FourierGgswCiphertext, FourierGlevCiphertext, GlevParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

impl<T: TorusFftValue> FourierGlweEncryptor<'_, T> {
    /// Encrypts an N-coefficient ring polynomial into all GLev levels without a
    /// plaintext codec. Every row is completed modulo the native modulus first.
    ///
    /// # Panics
    /// Key/parameter/input/output/FFT checks precede sampling or writes.
    /// RNG/FFT panics can consume randomness and partly write output.
    pub fn encrypt_glev_to<
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    >(
        &mut self,
        input: &Polynomial<A>,
        output: &mut FourierGlevCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_gadget_compatible(params, fft);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.fourier_glev_len(),
            "Fourier GLev output layout mismatch"
        );
        self.encrypt_glev_kernel_to(input.as_view(), output.as_mut_view(), params, fft, rng);
    }

    /// Caller checked complete input/output and target/FFT layouts once.
    pub(crate) fn encrypt_glev_kernel_to<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &mut self,
        input: Polynomial<&[T]>,
        mut output: FourierGlevCiphertext<&mut [Complex64]>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        for (scalar, row) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_glwe_mut(params.fourier_glwe_len()))
        {
            self.sample_row(params.encryption_parameters(), rng, |body| {
                for (b, &m) in body.iter_mut().zip(input.as_ref()) {
                    *b = b.wrapping_add(m.wrapping_mul(scalar));
                }
            });
            self.write_fourier_row(row, fft);
        }
    }

    /// Encrypts a ring polynomial into `[row][level][component]` Fourier GGSW
    /// storage, with gadget scaling and no plaintext codec. Mask-row diagonals
    /// are added after computing the body, preserving phase `e-g_i*M*s_row`.
    /// Every final component is reduced in the native ring before FFT.
    ///
    /// # Panics
    /// Key/parameter/input/output/FFT checks precede sampling or writes.
    /// RNG/FFT panics can consume randomness and partly write output.
    pub fn encrypt_ggsw_to<
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    >(
        &mut self,
        input: &Polynomial<A>,
        output: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        self.assert_gadget_compatible(params, fft);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.fourier_ggsw_len(),
            "Fourier GGSW output layout mismatch"
        );
        self.encrypt_ggsw_kernel_to(input.as_view(), output.as_mut_view(), params, fft, rng);
    }

    /// Streams row-major output with no independent diagonal spectrum cache.
    /// The caller checked layouts; each sampled native row receives its diagonal
    /// before conversion. Scaling directly avoids an extra message polynomial.
    pub(crate) fn encrypt_ggsw_kernel_to<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &mut self,
        input: Polynomial<&[T]>,
        mut output: FourierGgswCiphertext<&mut [Complex64]>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) {
        for (diagonal, mut glev) in output.iter_glev_mut(params.fourier_glev_len()).enumerate() {
            for (scalar, row) in params
                .basis()
                .scalar_iter()
                .zip(glev.iter_glwe_mut(params.fourier_glwe_len()))
            {
                self.sample_gadget_row(
                    diagonal,
                    params.encryption_parameters(),
                    rng,
                    |coefficients| {
                        for (out, &m) in coefficients.iter_mut().zip(input.as_ref()) {
                            *out = out.wrapping_add(m.wrapping_mul(scalar));
                        }
                    },
                );
                self.write_fourier_row(row, fft);
            }
        }
    }

    /// Validates the immutable target layout and FFT at a composite boundary.
    pub(crate) fn assert_gadget_compatible<Table: FftTable>(
        &self,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
    ) {
        assert_eq!(
            self.glwe_size(),
            params.glwe_size(),
            "GLWE parameter layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
    }
}

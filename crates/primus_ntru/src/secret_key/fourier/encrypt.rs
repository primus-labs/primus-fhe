//! Codec-free encoded and zero encryption.

use super::{FourierNtruEncryptWorkspace, FourierNtruSecretKey};
use crate::{FourierNtruCiphertext, NtruEncryptionParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

impl FourierNtruSecretKey {
    /// Encrypts coefficients already encoded in the native torus without scaling.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance supplied at key construction.
    ///
    /// # Panics
    ///
    /// Panics before sampling on inconsistent key/parameter/FFT/input/output or
    /// workspace lengths. A panicking RNG or FFT can modify output and scratch.
    pub fn encrypt_encoded_to<T, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        output: &mut FourierNtruCiphertext<B>,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), params, fft, workspace);
        assert_eq!(
            encoded.as_ref().len(),
            self.poly_length(),
            "NTRU encoded input length mismatch"
        );
        self.encrypt_encoded_to_unchecked(
            encoded.as_view(),
            output.as_mut_view(),
            params,
            fft,
            rng,
            workspace,
        );
    }

    /// Encrypts zero into a freshly allocated Fourier ciphertext.
    /// Inherits [`Self::encrypt_zeros_to`]'s transform and layout requirements.
    #[must_use]
    pub fn encrypt_zeros<T, Table, R>(
        &self,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) -> FourierNtruCiphertext<Vec<Complex64>>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = FourierNtruCiphertext::zero(fft.fourier_length());
        self.encrypt_zeros_to(&mut output, params, fft, rng, workspace);
        output
    }

    /// Encrypts canonical coefficients after the ordinary or gadget boundary validates
    /// complete operands and backend resources. No codec or gadget scaling is applied here.
    pub(super) fn encrypt_encoded_to_unchecked<T, Table, R>(
        &self,
        encoded: Polynomial<&[T]>,
        output: FourierNtruCiphertext<&mut [Complex64]>,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(encoded.as_ref().len(), self.poly_length());
        debug_assert_eq!(output.as_ref().len(), fft.fourier_length());
        self.encrypt_kernel_to(output, params, fft, rng, workspace, |coefficients| {
            Polynomial(coefficients).add_assign(&encoded, NativeModulus::new());
        });
    }

    /// Encrypts the zero polynomial into the existing output without allocating.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance supplied at key construction.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if key/parameter/FFT/output/workspace
    /// lengths disagree.
    pub fn encrypt_zeros_to<T, Table, R, B>(
        &self,
        output: &mut FourierNtruCiphertext<B>,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), params, fft, workspace);
        self.encrypt_zeros_to_unchecked(output.as_mut_view(), params, fft, rng, workspace);
    }

    /// Encrypts zero after the ordinary or gadget boundary validates output and resources.
    pub(super) fn encrypt_zeros_to_unchecked<T, Table, R>(
        &self,
        output: FourierNtruCiphertext<&mut [Complex64]>,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(output.as_ref().len(), fft.fourier_length());
        self.encrypt_kernel_to(output, params, fft, rng, workspace, |_| {});
    }

    /// Validates ordinary output and backend resources before sampling or writes.
    pub(super) fn assert_encrypt_compatible<T, Table>(
        &self,
        output_len: usize,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierNtruEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
    {
        self.assert_domain(params, fft);
        assert_eq!(
            output_len,
            fft.fourier_length(),
            "Fourier NTRU output length mismatch"
        );
        self.assert_encrypt_workspace(workspace);
    }

    pub(super) fn assert_encrypt_workspace<T: TorusFftValue>(
        &self,
        workspace: &FourierNtruEncryptWorkspace<T>,
    ) {
        assert_eq!(
            workspace.coeff.as_ref().len(),
            self.poly_length(),
            "NTRU coefficient workspace length mismatch"
        );
    }

    /// Transforms only the already reduced native ciphertext coefficients.
    pub(super) fn encrypt_kernel_to<T, Table, R>(
        &self,
        mut output: FourierNtruCiphertext<&mut [Complex64]>,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
        add_message: impl FnOnce(&mut [T]),
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_coefficients_to_workspace(params, rng, workspace, add_message);
        fft.forward_as_torus(workspace.coeff.as_ref(), output.as_mut());
    }

    /// The caller validates resources before invoking this native-ring kernel.
    /// Multiplying the noise and message by the exact native inverse before any
    /// FFT ensures the published representation derives from a reduced ciphertext.
    pub(super) fn encrypt_coefficients_to_workspace<T, R>(
        &self,
        params: &NtruEncryptionParameters<T, NativeModulus<T>>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
        add_message: impl FnOnce(&mut [T]),
    ) where
        T: TorusFftValue,
        R: rand::Rng + rand::CryptoRng,
    {
        let coefficients = workspace.coeff.as_mut();
        primus_distr::sample_gaussian_values_to(coefficients, params.noise_distribution(), rng);
        add_message(coefficients);
        workspace
            .product
            .multiply_assign(&self.native_inverse, coefficients);
    }
}

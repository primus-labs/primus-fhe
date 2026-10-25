//! Native-torus Fourier GLWE encryption.

use super::{FourierGlweEncryptWorkspace, FourierGlweSecretKey};
use crate::{FourierGlweCiphertext, GlweEncryptionParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;

impl FourierGlweSecretKey {
    /// Encrypts a polynomial whose coefficients are already encoded in the
    /// native torus ciphertext space. No plaintext codec is needed; the key
    /// supplies the layout. Use [`Self::decrypt_phase_to`] to recover the noisy coefficients.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the input/output, FFT or workspace
    /// lengths disagree with the key layout.
    pub fn encrypt_encoded_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
        T: TorusFftValue,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), fft, workspace);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
        self.encrypt_encoded_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            fft,
            rng,
            workspace,
        );
    }

    /// Encrypts zero into a native-torus Fourier-domain GLWE ciphertext.
    ///
    /// # Panics
    ///
    /// Inherits the resource checks of [`Self::encrypt_zeros_to`].
    #[must_use]
    pub fn encrypt_zeros<T, Table, R>(
        &self,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) -> FourierGlweCiphertext<Vec<Complex64>>
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        T: TorusFftValue,
    {
        let mut output = FourierGlweCiphertext::zero(self.size.fourier_glwe_len());
        self.encrypt_zeros_to(&mut output, params, fft, rng, workspace);
        output
    }

    /// Encrypts zero into an existing native-torus Fourier-domain GLWE ciphertext.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the output, FFT or workspace lengths
    /// disagree with the key layout.
    pub fn encrypt_zeros_to<T, Table, R, B>(
        &self,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
        T: TorusFftValue,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), fft, workspace);
        self.encrypt_zeros_kernel_to(output.as_mut_view(), params, fft, rng, workspace);
    }

    /// Encrypts an encoded coefficient polynomial without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel; the workspace must also match the key.
    /// Input length must equal the key's polynomial length; coefficients must be
    /// canonical in the ciphertext ring. No plaintext or gadget scaling is applied.
    #[inline]
    pub(super) fn encrypt_encoded_kernel_to<T, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: FourierGlweCiphertext<&mut [Complex64]>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        T: TorusFftValue,
    {
        self.encrypt_kernel_to(output, params, fft, rng, workspace, |body| {
            Polynomial::new(body).add_assign(&input, NativeModulus::new());
        });
    }

    /// Encrypts zero without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel; the workspace must also match the key.
    #[inline]
    pub(super) fn encrypt_zeros_kernel_to<T, Table, R>(
        &self,
        output: FourierGlweCiphertext<&mut [Complex64]>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        T: TorusFftValue,
    {
        self.encrypt_kernel_to(output, params, fft, rng, workspace, |_| {});
    }

    /// Validates layout and transform compatibility before sampling or writing output.
    #[inline]
    pub(super) fn assert_encrypt_compatible<T, Table>(
        &self,
        output_len: usize,
        fft: &FftEngine<'_, Table>,
        workspace: &FourierGlweEncryptWorkspace<T>,
    ) where
        Table: FftTable,
        T: TorusFftValue,
    {
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            output_len,
            self.size.fourier_glwe_len(),
            "Fourier GLWE output layout mismatch"
        );
        workspace.assert_poly_length(self.poly_length().get());
    }

    /// Encrypts with validated layouts and matching parameter/transform domains.
    /// Calls `add_message` once on the sampled coefficient noise, before transforming
    /// the body. Its concrete closure type specializes plaintext/encoded/zero paths
    /// without dynamic dispatch or an intermediate message buffer.
    pub(super) fn encrypt_kernel_to<T, Table, R>(
        &self,
        mut output: FourierGlweCiphertext<&mut [Complex64]>,
        params: &GlweEncryptionParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
        add_message: impl FnOnce(&mut [T]),
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        T: TorusFftValue,
    {
        let poly_length = self.size.poly_length().get();

        debug_assert_eq!(fft.poly_length().get(), poly_length);
        debug_assert_eq!(output.as_ref().len(), self.size.fourier_glwe_len());
        let fourier_length = fft.fourier_length();
        let (mask, mut body) = output.a_b_mut(fourier_length);

        let coeff = workspace.coeff.as_mut();
        debug_assert_eq!(coeff.len(), poly_length);
        primus_distr::sample_gaussian_values_to(coeff, params.noise_distribution(), rng);
        add_message(coeff);
        fft.forward_as_torus(coeff, body.as_mut());

        let uniform = params.cipher_modulus_uniform_distr();

        for (mut ai, si) in mask.zip(self.iter()) {
            primus_distr::sample_uniform_values_to(coeff, &uniform, rng);
            fft.forward_as_torus(coeff, ai.as_mut_slice());
            body.add_mul_assign(&ai, &si);
        }
    }
}

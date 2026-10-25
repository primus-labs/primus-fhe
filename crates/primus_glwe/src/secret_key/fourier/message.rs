//! Message adapters encode into the final body or existing coefficient scratch.

use super::{FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweSecretKey};
use crate::{FourierGlweCiphertext, GlweParameters, PlaintextEmbedding};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};

impl FourierGlweSecretKey {
    /// Encrypts a message polynomial into a newly allocated ciphertext.
    /// Uses the same embedding and contracts as [`Self::encrypt_message_to`].
    ///
    /// # Panics
    ///
    /// Inherits the layout and plaintext-range panic conditions of [`Self::encrypt_message_to`].
    #[must_use]
    pub fn encrypt_message<T, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) -> FourierGlweCiphertext<Vec<Complex64>>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = FourierGlweCiphertext::zero(self.size.fourier_glwe_len());
        self.encrypt_message_to(input, &mut output, params, embedding, fft, rng, workspace);
        output
    }

    /// Encrypts a message polynomial with the selected embedding into a native-torus Fourier-domain ciphertext.
    /// Both embeddings accept canonical residues in `[0, t)`; centered `t - 1`
    /// represents `-1`. Encoding is added to the sampled body noise in place.
    ///
    /// # Panics
    ///
    /// Panics if the key, parameter layout, transform and workspace, message length,
    /// or output length are incompatible. Compatibility is checked before
    /// writing the ciphertext.
    ///
    /// Also panics if any plaintext coefficient is outside `[0, t)`. That check
    /// occurs in the codec and may leave partial output or consume randomness.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit embedding and encryption resources"
    )]
    pub fn encrypt_message_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
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
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.assert_encrypt_compatible(output.as_ref().len(), fft, workspace);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
        self.encrypt_message_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            embedding,
            fft,
            rng,
            workspace,
        );
    }

    /// Builds the plaintext body addition after storage has been normalized to views.
    /// The caller has validated all layouts/resources; plaintext range checks still
    /// run in the codec after noise sampling, preserving partial-write/RNG behavior.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit message embedding and encryption resources"
    )]
    fn encrypt_message_kernel_to<T, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: FourierGlweCiphertext<&mut [Complex64]>,
        params: &GlweParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierGlweEncryptWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(
            output,
            params.encryption_parameters(),
            fft,
            rng,
            workspace,
            |body| {
                params
                    .plaintext_codec()
                    .add_encode_slice_assign(body, input.as_ref(), embedding);
            },
        );
    }

    /// Decrypts a native-torus Fourier-domain GLWE ciphertext.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    #[must_use]
    pub fn decrypt_message<T, Table, A>(
        &self,
        input: &FourierGlweCiphertext<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) -> PolynomialOwned<T>
    where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        T: TorusFftValue,
    {
        let mut output = PolynomialOwned::zero(self.size.poly_length().get());
        self.decrypt_message_to(input, &mut output, params, fft, workspace);
        output
    }

    /// Decrypts into an existing plaintext polynomial.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements.
    /// Returns canonical residues in `[0, t)` for either encryption embedding.
    /// Recovering the original message requires phase noise within the codec margin.
    ///
    /// # Panics
    ///
    /// Panics if the parameter layout differs from this key or the inputs
    /// violate [`Self::decrypt_phase_to`]'s compatibility checks.
    pub fn decrypt_message_to<T, Table, A, B>(
        &self,
        input: &FourierGlweCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweDecryptWorkspace,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
        T: TorusFftValue,
    {
        assert_eq!(self.size, params.size(), "GLWE parameter layout mismatch");
        self.decrypt_phase_to(input, output, fft, workspace);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}

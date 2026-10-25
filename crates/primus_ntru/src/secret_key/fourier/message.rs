//! Message adapters encode into the output or existing coefficient scratch.

use super::{FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruSecretKey};
use crate::{FourierNtruCiphertext, NtruParameters};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};

impl FourierNtruSecretKey {
    /// Encrypts a message polynomial into a newly allocated Fourier-domain NTRU ciphertext.
    /// Inherits [`Self::encrypt_message_to`]'s input and transform requirements.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_message_to`]'s layout and plaintext-range panic conditions.
    #[must_use]
    pub fn encrypt_message<T, Table, R, A>(
        &self,
        input: &Polynomial<A>,
        params: &NtruParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
    ) -> FourierNtruCiphertext<Vec<Complex64>>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut output = FourierNtruCiphertext::zero(fft.fourier_length());
        self.encrypt_message_to(input, &mut output, params, embedding, fft, rng, workspace);
        output
    }

    /// Encrypts a message polynomial with the selected embedding into `output`.
    /// Both embeddings accept canonical residues in `[0, t)`; centered `t - 1`
    /// represents `-1`. Encoding is added to the sampled coefficient noise in place.
    ///
    /// `input` has `N` values in `[0, t)`; `output` has `N/2` complex values.
    /// Reuses the supplied workspace.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance supplied at key construction.
    ///
    /// # Panics
    ///
    /// Panics before sampling on inconsistent key/parameter/FFT/input/output or
    /// workspace lengths. A plaintext-codec panic can modify scratch and consume
    /// randomness; a panicking FFT can also leave partial output.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit embedding and encryption resources"
    )]
    pub fn encrypt_message_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
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
        self.assert_encrypt_compatible(
            output.as_ref().len(),
            params.encryption_parameters(),
            fft,
            workspace,
        );
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "NTRU message length mismatch"
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

    /// Builds the codec addition after normalizing storage to borrowed views.
    /// Layout/domain checks precede this call; the codec checks message values after
    /// noise sampling, preserving partial-write and RNG-consumption behavior.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit embedding and encryption resources"
    )]
    fn encrypt_message_kernel_to<T, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: FourierNtruCiphertext<&mut [Complex64]>,
        params: &NtruParameters<T, NativeModulus<T>>,
        embedding: PlaintextEmbedding,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        workspace: &mut FourierNtruEncryptWorkspace<T>,
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
            |coefficients| {
                params.plaintext_codec().add_encode_slice_assign(
                    coefficients,
                    input.as_ref(),
                    embedding,
                );
            },
        );
    }

    /// Decrypts to unsigned plaintext values in `[0, t)`.
    /// Both unsigned and centered embeddings use this decoder.
    /// Inherits [`Self::decrypt_message_to`]'s representation and recovery requirements.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::decrypt_message_to`]'s parameter and layout checks.
    #[must_use]
    pub fn decrypt_message<T, Table, A>(
        &self,
        input: &FourierNtruCiphertext<A>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruDecryptWorkspace,
    ) -> PolynomialOwned<T>
    where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
    {
        let mut output = PolynomialOwned::zero(self.poly_length());
        self.decrypt_message_to(input, &mut output, params, fft, workspace);
        output
    }

    /// Decrypts into an existing message polynomial, returning canonical `[0, t)` residues.
    /// Inherits [`Self::decrypt_phase_to`]'s representation requirements. Recovering
    /// the original message requires phase error within the codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics before writes if the parameter length differs from this key or the
    /// inputs violate [`Self::decrypt_phase_to`]'s compatibility checks.
    pub fn decrypt_message_to<T, Table, A, B>(
        &self,
        input: &FourierNtruCiphertext<A>,
        output: &mut Polynomial<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruDecryptWorkspace,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            params.poly_length().get(),
            self.poly_length(),
            "NTRU parameter length mismatch"
        );
        self.decrypt_phase_to(input, output, fft, workspace);
        params
            .plaintext_codec()
            .decode_slice_assign(output.as_mut());
    }
}

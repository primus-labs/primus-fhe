//! Client-side coefficient-ring encryption and decryption under the accumulator secret.

use primus_data::{Data, DataMut};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweCiphertext, FourierGlweDecryptWorkspace, FourierGlweEncryptor, FourierGlweSecretKey,
    GlweCiphertext, GlweParameters, GlweSecretKey,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::RingContext;

use crate::{TfheClientError, TfheContext};

/// Prepared private-key client for the accumulator GLWE domain.
///
/// Borrows the FFT table and coefficient secret, owning exact encryption setup,
/// a Fourier decryption cache and independently bound message parameters.
/// Ciphertexts use coefficient representation and the accumulator secret, which
/// differs from the external LWE domain used by [`crate::Encryptor`].
/// Construction prepares all buffers; `encrypt_to` and `decrypt_to` do not allocate.
pub struct AccumulatorClient<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    parameters: GlweParameters<T, NativeModulus<T>>,
    secret: FourierGlweSecretKey,
    transformed: FourierGlweCiphertext<Vec<Complex64>>,
    fft: FftEngine<'a, Table>,
    encrypt: FourierGlweEncryptor<'a, T>,
    decrypt: FourierGlweDecryptWorkspace,
}

impl<'a, T, Table> AccumulatorClient<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds only the accumulator secret and a Scaled message codec to the accumulator domain.
    /// Rejects an incompatible key or codec modulus before preparing the secret.
    pub fn try_new<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        secret_key: &'a GlweSecretKey<T>,
        codec: ScaledCodec<T, NativeModulus<T>>,
    ) -> Result<Self, TfheClientError> {
        context
            .parameters()
            .check_accumulator_secret_key(secret_key)?;
        let parameters =
            GlweParameters::try_from_glev(context.parameters().blind_rotation_params(), codec)
                .map_err(|_| crate::ClientError::CodecModulusMismatch)?;
        let encrypt = FourierGlweEncryptor::try_new(secret_key, parameters.encryption_parameters())
            .map_err(crate::error::glwe_encryption_error)?;
        let mut fft = context.new_fft_engine();
        let secret = FourierGlweSecretKey::from_coeff_secret_key(secret_key, &mut fft);
        Ok(Self {
            secret,
            transformed: FourierGlweCiphertext::zero(parameters.size().fourier_glwe_len()),
            fft,
            encrypt,
            decrypt: FourierGlweDecryptWorkspace::new(parameters.poly_length()),
            parameters,
        })
    }

    /// Encrypts an unsigned polynomial into a newly allocated coefficient ciphertext.
    /// Inherits [`Self::encrypt_to`]'s message and panic contracts.
    #[must_use]
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        message: &[T],
        rng: &mut R,
    ) -> GlweCiphertext<Vec<T>> {
        let mut output = GlweCiphertext::zero(self.parameters.glwe_len());
        self.encrypt_to(message, &mut output, rng);
        output
    }

    /// Encrypts exactly N unsigned coefficients in `[0, t)` under the accumulator secret.
    /// Uses this client's Scaled codec and overwrites the entire coefficient output.
    ///
    /// # Panics
    /// Panics before sampling if message or output length is wrong. A plaintext-range
    /// or RNG panic may consume randomness and modify scratch, leaving output
    /// untouched. No FFT is performed. See
    /// [`FourierGlweEncryptor::encrypt_message_coeff_to`].
    pub fn encrypt_to<R, S>(&mut self, message: &[T], output: &mut GlweCiphertext<S>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        S: DataMut<Elem = T>,
    {
        let parameters = &self.parameters;
        self.encrypt.encrypt_message_coeff_to(
            &Polynomial::new(message),
            output,
            parameters,
            PlaintextEmbedding::Unsigned,
            rng,
        );
    }

    /// Allocates and decodes all N coefficients. Inherits [`Self::decrypt_to`]'s contracts.
    #[must_use]
    pub fn decrypt<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>) -> Vec<T> {
        let mut output = vec![T::ZERO; self.parameters.poly_length().get()];
        self.decrypt_to(input, &mut output);
        output
    }

    /// Decodes to exactly N unsigned coefficients in `[0, t)`, overwriting `output`.
    ///
    /// # Correctness
    /// Input must use this accumulator secret, modulus and plaintext codec, with
    /// noise within the decoding margin. Ciphertexts carry no key/encoding metadata.
    ///
    /// # Panics
    /// Panics before output writes if ciphertext or plaintext length is wrong.
    pub fn decrypt_to<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>, output: &mut [T]) {
        let parameters = &self.parameters;
        assert_eq!(
            (input.as_ref().len(), output.len()),
            (parameters.glwe_len(), parameters.poly_length().get()),
            "accumulator decryption layout mismatch"
        );
        input.write_fourier_form(&mut self.transformed, &mut self.fft);
        self.secret.decrypt_message_to(
            &self.transformed,
            &mut Polynomial::new(output),
            parameters,
            &mut self.fft,
            &mut self.decrypt,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Builds Scaled encoding at ring Q for `t_ring`, independently of the
    /// external LWE input/output message moduli and CBS gadget scales.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client<'a>(
        &'a self,
        secret_key: &'a GlweSecretKey<T>,
        t_ring: T,
    ) -> Result<crate::AccumulatorClient<'a, T, Table>, crate::TfheClientError> {
        let codec = ScaledCodec::try_new(t_ring, self.parameters().ring_modulus())
            .map_err(crate::ClientError::from)?;
        crate::AccumulatorClient::try_new(self, secret_key, codec)
    }
}

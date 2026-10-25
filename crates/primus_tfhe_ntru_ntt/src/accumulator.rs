//! Client-side coefficient-ring encryption and decryption under the accumulator secret.

use primus_data::{Data, DataMut};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_integer::FheUint;
use primus_ntru::{
    NtruCiphertext, NtruParameters, NtruSecretKey, NttNtruCiphertext, NttNtruSecretKey,
};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;

use crate::{TfheClientError, TfheContext};

/// Prepared private-key client for the accumulator NTRU domain.
///
/// Owns one transformed accumulator secret and reusable conversion workspace,
/// binding a message codec and borrowing the context that fixes its table and modulus.
/// Ciphertexts use coefficient representation and the accumulator secret, which
/// differs from the external LWE domain used by [`crate::Encryptor`].
/// Construction prepares all buffers; `encrypt_to` and `decrypt_to` do not allocate.
pub struct AccumulatorClient<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    parameters: NtruParameters<T, primus_modulus::BarrettModulus<T>>,
    secret: NttNtruSecretKey<T>,
    transformed: NttNtruCiphertext<Vec<T>>,
}

impl<'a, T, Table, LM> AccumulatorClient<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Validates the key and Scaled codec modulus Q, then prepares the accumulator secret.
    /// Requires only the accumulator secret; its message codec is independent
    /// of external LWE encoding.
    /// Returns NTRU conversion failures, including a noninvertible secret.
    ///
    /// # Correctness
    /// Imported accumulator coefficients must have unsigned magnitude below Q;
    /// see [`NttNtruSecretKey::try_from_coeff_secret_key`]. Layout checks do not establish this bound.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        secret_key: &NtruSecretKey<T>,
        codec: ScaledCodec<T, primus_modulus::BarrettModulus<T>>,
    ) -> Result<Self, TfheClientError> {
        context
            .parameters()
            .check_accumulator_secret_key(secret_key)?;
        let parameters =
            NtruParameters::try_from_nlev(context.parameters().blind_rotation(), codec)
                .map_err(|_| crate::ClientError::CodecModulusMismatch)?;
        let secret = NttNtruSecretKey::try_from_coeff_secret_key(
            secret_key,
            parameters.cipher_modulus(),
            context.table(),
        )?;
        Ok(Self {
            context,
            secret,
            transformed: NttNtruCiphertext::zero(parameters.poly_length().get()),
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
    ) -> NtruCiphertext<Vec<T>> {
        let mut output = self.context.allocate_accumulator_ciphertext();
        self.encrypt_to(message, &mut output, rng);
        output
    }

    /// Encrypts exactly N unsigned coefficients in `[0, t)` under the accumulator secret.
    /// Uses the accumulator plaintext codec and overwrites the entire coefficient output.
    ///
    /// # Panics
    /// Panics before sampling if message or output length is wrong. A plaintext-range
    /// or RNG panic may consume randomness and modify scratch; transform panics may
    /// partially write output. See
    /// [`NttNtruSecretKey::encrypt_message_to`].
    pub fn encrypt_to<R, S>(&mut self, message: &[T], output: &mut NtruCiphertext<S>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        S: DataMut<Elem = T>,
    {
        let parameters = &self.parameters;
        let n = parameters.poly_length().get();
        assert_eq!(
            (message.len(), output.as_ref().len()),
            (n, n),
            "accumulator encryption layout mismatch"
        );
        self.secret.encrypt_message_to(
            &Polynomial::new(message),
            &mut self.transformed,
            parameters,
            PlaintextEmbedding::Unsigned,
            self.context.table(),
            rng,
        );
        self.transformed
            .write_coeff_form(output, self.context.table());
    }

    /// Allocates and decodes all N coefficients. Inherits [`Self::decrypt_to`]'s contracts.
    #[must_use]
    pub fn decrypt<S: Data<Elem = T>>(&mut self, input: &NtruCiphertext<S>) -> Vec<T> {
        let n = self
            .context
            .parameters()
            .accumulator_ntru()
            .poly_length()
            .get();
        let mut output = vec![T::ZERO; n];
        self.decrypt_to(input, &mut output);
        output
    }

    /// Decodes to exactly N unsigned coefficients in `[0, t)`, overwriting `output`.
    ///
    /// # Correctness
    /// Input must use this accumulator secret, modulus and plaintext codec, with
    /// canonical residues and noise within the decoding margin. Ciphertexts carry no
    /// key/encoding metadata.
    ///
    /// # Panics
    /// Panics before output writes if ciphertext or plaintext length is wrong.
    pub fn decrypt_to<S: Data<Elem = T>>(&mut self, input: &NtruCiphertext<S>, output: &mut [T]) {
        let parameters = &self.parameters;
        let n = parameters.poly_length().get();
        assert_eq!(
            (input.as_ref().len(), output.len()),
            (n, n),
            "accumulator decryption layout mismatch"
        );
        input.write_ntt_form(&mut self.transformed, self.context.table());
        self.secret.decrypt_message_to(
            &self.transformed,
            &mut Polynomial::new(output),
            parameters,
            self.context.table(),
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Builds Scaled encoding at ring Q for `t_ring`, independently of the
    /// external LWE input/output message moduli and CBS gadget scales.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client(
        &self,
        secret_key: &NtruSecretKey<T>,
        t_ring: T,
    ) -> Result<crate::AccumulatorClient<'_, T, Table, LM>, TfheClientError> {
        let codec = ScaledCodec::try_new(
            t_ring,
            self.parameters().accumulator_ntru().cipher_modulus(),
        )
        .map_err(crate::ClientError::from)?;
        crate::AccumulatorClient::try_new(self, secret_key, codec)
    }
}

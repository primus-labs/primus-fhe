//! Client-side coefficient-ring encryption and decryption under the accumulator secret.

use primus_data::{Data, DataMut};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_glwe::{GlweCiphertext, GlweParameters, GlweSecretKey, NttGlweSecretKey};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use zeroize::Zeroizing;

use crate::{TfheClientError, TfheContext};

/// Prepared private-key client for the accumulator GLWE domain.
///
/// Borrows the accumulator NTT table and owns one transformed accumulator secret
/// and an N-coefficient scratch buffer, both erased on drop. The selected codec
/// is bound once to the context's ring domain.
/// Ciphertexts use coefficient representation and the accumulator secret, which
/// differs from the external LWE domain used by [`crate::Encryptor`].
/// Construction prepares all buffers; `encrypt_to` and `decrypt_to` do not allocate.
pub struct AccumulatorClient<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    table: &'a Table,
    parameters: GlweParameters<T, BarrettModulus<T>>,
    secret: NttGlweSecretKey<T>,
    scratch: Zeroizing<Vec<T>>,
}

impl<'a, T, Table> AccumulatorClient<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Binds only the accumulator secret and a Scaled message codec to the accumulator domain.
    /// Rejects an incompatible key or codec modulus before preparing the secret.
    ///
    /// # Correctness
    /// Imported accumulator coefficients must have unsigned magnitude below q;
    /// see [`NttGlweSecretKey::from_coeff_secret_key`]. Layout checks do not establish this bound.
    pub fn try_new<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        secret_key: &GlweSecretKey<T>,
        codec: ScaledCodec<T, BarrettModulus<T>>,
    ) -> Result<Self, TfheClientError>
    where
        Table: MonomialNttTable,
    {
        let pbs = context.parameters();
        pbs.check_accumulator_secret_key(secret_key)?;
        let parameters = GlweParameters::try_from_glev(pbs.blind_rotation_params(), codec)
            .map_err(|_| crate::ClientError::CodecModulusMismatch)?;
        let table = context.table();
        let secret = NttGlweSecretKey::from_coeff_secret_key(secret_key, table);
        Ok(Self {
            table,
            secret,
            scratch: Zeroizing::new(vec![T::ZERO; parameters.poly_length().get()]),
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
    /// or RNG/transform panic may consume randomness and partially write output
    /// or scratch. See [`NttGlweSecretKey::encrypt_message_coeff_to`].
    pub fn encrypt_to<R, S>(&mut self, message: &[T], output: &mut GlweCiphertext<S>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        S: DataMut<Elem = T>,
    {
        let parameters = &self.parameters;
        self.secret.encrypt_message_coeff_to(
            &Polynomial::new(message),
            output,
            parameters,
            PlaintextEmbedding::Unsigned,
            self.table,
            rng,
            &mut self.scratch,
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
    /// canonical residues and noise within the decoding margin. Ciphertexts carry no
    /// key/encoding metadata.
    ///
    /// # Panics
    /// Panics before output writes if ciphertext or plaintext length is wrong.
    pub fn decrypt_to<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>, output: &mut [T]) {
        let parameters = &self.parameters;
        self.secret.decrypt_message_coeff_to(
            input,
            &mut Polynomial::new(output),
            parameters,
            self.table,
            &mut self.scratch,
        );
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Builds Scaled encoding at ring Q for `t_ring`, independently of the
    /// external LWE input/output message moduli and CBS gadget scales.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client(
        &self,
        secret_key: &GlweSecretKey<T>,
        t_ring: T,
    ) -> Result<crate::AccumulatorClient<'_, T, Table>, crate::TfheClientError> {
        let codec = ScaledCodec::try_new(t_ring, self.parameters().ring_modulus())
            .map_err(crate::ClientError::from)?;
        crate::AccumulatorClient::try_new(self, secret_key, codec)
    }
}

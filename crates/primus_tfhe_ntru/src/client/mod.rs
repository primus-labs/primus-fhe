use primus_encoding::{MessageDecoder, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_lwe::{LwePublicKey, LweSecretKey};
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, EncryptionKey, Encryptor, LweClientParameters};

use crate::{PbsParameters, TfheClientError, TfheKeyError};

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Binds the configured Rounded input shared by PBS, ManyLUT and factorized MVB.
    /// Copies the encoding state and borrows the external secret and its fresh
    /// noise sampler at q. The accumulator modulus Q does not affect this client.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a LweSecretKey<T>,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        self.encryptor_with_message_modulus(key, self.messages().input_modulus)
    }

    /// Binds a Rounded input message modulus without changing configured defaults.
    /// Reuses the external secret, q and prepared noise sampler. Pair with the
    /// compiler's `messages.input_modulus`; capacity is checked by the compiler.
    ///
    /// # Correctness
    /// Changed message spacing needs a fresh-encryption and PBS-input noise budget.
    pub fn encryptor_with_message_modulus<'a>(
        &'a self,
        key: &'a LweSecretKey<T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        Ok(self.input_encryptor(key.as_view(), message_modulus)?)
    }

    /// Binds the configured Rounded input at external q to an LWE public key.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, LM, &'a LwePublicKey<T>>, ClientError> {
        self.public_encryptor_with_message_modulus(key, self.messages().input_modulus)
    }

    /// Binds a Rounded input override to the existing external public key.
    /// Shares [`Self::encryptor_with_message_modulus`]'s message/ciphertext domains
    /// and [`primus_tfhe::EncryptionKey`]'s public-key identity and noise contracts.
    pub fn public_encryptor_with_message_modulus<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, LM, &'a LwePublicKey<T>>, ClientError> {
        self.input_encryptor(key, message_modulus)
    }

    /// Binds the configured Rounded output for ordinary PBS and ManyLUT.
    /// Prepares decoding at returned LWE modulus q, independently of LUT modulus Q.
    /// Copies decoding state and borrows only the external secret. Factorized MVB
    /// outputs require [`Self::mvb_decryptor`] instead.
    ///
    /// # Correctness
    /// Inherits [`Self::decryptor_with_codec`]'s recovery contract, including Q→q
    /// rounding and key-switch noise when these stages are used.
    pub fn pbs_decryptor<'a>(
        &self,
        key: &'a LweSecretKey<T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.pbs_decryptor_with_message_modulus(key, self.messages().output_modulus)
    }

    /// Binds a Rounded PBS/ManyLUT output override at external q.
    /// Pair with the compiler's `messages.output_modulus`; input messages and
    /// defaults remain unchanged. Scaled outputs use [`Self::ring_return_decryptor`].
    ///
    /// # Correctness
    /// Inherits [`Self::decryptor_with_codec`]'s recovery contract. The producing
    /// operation must use this message modulus and Rounded encoding.
    pub fn pbs_decryptor_with_message_modulus<'a>(
        &self,
        key: &'a LweSecretKey<T>,
        message_modulus: T,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        let codec = RoundedCodec::try_new(message_modulus, self.external_lwe().cipher_modulus())
            .map_err(ClientError::from)?;
        Ok(Decryptor::new(&codec, key.as_view()))
    }

    /// Binds the configured Scaled output for factorized MVB at returned LWE modulus q.
    /// Copies decoding state and borrows only the external secret. Codec validity
    /// does not establish the factor amplification, transform or Q→q return noise budget.
    ///
    /// # Correctness
    /// Inherits [`Self::decryptor_with_codec`]'s recovery contract.
    pub fn mvb_decryptor<'a>(
        &self,
        key: &'a LweSecretKey<T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.ring_return_decryptor(key, self.messages().output_modulus)
    }

    /// Decodes a returned Scaled ring phase with explicit message modulus `t_ring`.
    /// Prepares decoding at external q without changing the PBS/MVB message moduli.
    ///
    /// # Correctness
    /// `t_ring` must match the original ring encoding. Budget the difference
    /// between the rescaled Q-encoding center and the q-encoding center as well
    /// as ring-operation, Q→q rounding and f→s KS error; see
    /// [`Self::decryptor_with_codec`].
    pub fn ring_return_decryptor<'a>(
        &self,
        key: &'a LweSecretKey<T>,
        t_ring: T,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        let codec = ScaledCodec::try_new(t_ring, self.external_lwe().cipher_modulus())
            .map_err(ClientError::from)?;
        Ok(Decryptor::new(&codec, key.as_view()))
    }

    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// Only this external secret is checked; no other setup secret is required.
    /// Copies a prepared codec, as used by high-precision LUT contexts. For a
    /// message-only override, use [`Self::encryptor_with_message_modulus`].
    /// Noise and programmable capacity remain caller requirements.
    pub fn encryptor_with_codec<'a>(
        &'a self,
        key: &'a LweSecretKey<T>,
        codec: &RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        Ok(Encryptor::try_new(
            self.client_parameters(codec)?,
            key.as_view(),
        )?)
    }

    /// Binds the active external secret and a decoder at the key's ciphertext modulus.
    /// Copies prepared Rounded or Scaled decoding state, as used by high-precision
    /// LUT contexts. Message-only overrides use [`Self::pbs_decryptor_with_message_modulus`]
    /// or [`Self::ring_return_decryptor`] with explicit output semantics.
    ///
    /// # Correctness
    /// Its message modulus and recovery bound must match the ciphertext. For
    /// bootstrapped returns, include Q→q rounding and key-switch noise in that bound.
    pub fn decryptor_with_codec<'a>(
        &self,
        key: &'a LweSecretKey<T>,
        codec: impl Into<MessageDecoder<T, LM>>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        let decoder = codec.into();
        self.check_codec_modulus(decoder.ciphertext_modulus())?;
        Ok(Decryptor::new(decoder, key.as_view()))
    }

    /// Generates an LWE public key using only the external secret and its fresh noise.
    /// No accumulator secret, transform table or return-key material is required.
    ///
    /// # Correctness
    /// Public-key usage and security follow [`crate::LwePublicKey`] and
    /// [`crate::EncryptionKey`]; shape/domain checks do not prove secret identity.
    ///
    /// # Errors
    /// Rejects incompatible external dimensions, distributions, residues or modulus.
    ///
    /// # Panics
    /// Panics if public-key storage `n * (n + 1)` overflows for external dimension n.
    pub fn try_generate_public_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        key: &LweSecretKey<T>,
        rng: &mut R,
    ) -> Result<LwePublicKey<T>, TfheKeyError> {
        self.check_external_secret_key(key)?;
        let lwe = self.external_lwe();
        Ok(LwePublicKey::generate(
            key.as_view(),
            lwe.dimension(),
            lwe.cipher_modulus(),
            lwe.cipher_modulus_uniform_distr(),
            lwe.noise_distribution(),
            rng,
        ))
    }

    // The caller binds the owning secret; public keys check themselves in
    // Encryptor::try_new. The constructed codec already uses this domain's q.
    fn input_encryptor<Key: EncryptionKey<T, LM>>(
        &self,
        key: Key,
        message_modulus: T,
    ) -> Result<Encryptor<'_, T, LM, Key>, ClientError> {
        let lwe = self.external_lwe();
        let codec = RoundedCodec::try_new(message_modulus, lwe.cipher_modulus())?;
        let parameters =
            LweClientParameters::try_from_parts(lwe.dimension(), &codec, lwe.noise_distribution())?;
        Encryptor::try_new(parameters, key)
    }

    fn check_codec_modulus(&self, modulus: LM) -> Result<(), ClientError> {
        if modulus.explicit_value() != self.external_lwe().cipher_modulus().explicit_value() {
            return Err(ClientError::CodecModulusMismatch);
        }
        Ok(())
    }

    // The external LWE secret and its fresh noise are independent of Q and message t.
    fn client_parameters<'a>(
        &'a self,
        codec: &RoundedCodec<T, LM>,
    ) -> Result<LweClientParameters<'a, T, LM>, ClientError> {
        self.check_codec_modulus(codec.ciphertext_modulus())?;
        let noise = self.external_lwe().noise_distribution();
        LweClientParameters::try_from_parts(self.external_lwe_dimension(), codec, noise)
    }
}

//! External LWE client constructors for the bound TFHE context.

use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;

use crate::{
    CbsEncryptor, ClientError, Decryptor, Encryptor, ExternalLweSecretKey, TfheClientError,
    TfheContext,
};

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Binds the configured Rounded input shared by PBS, ManyLUT and factorized MVB.
    /// Use [`Self::cbs_encryptor`] for the separately configured CBS input.
    ///
    /// Copies the encoding state and borrows only the external secret and fresh
    /// noise sampler. No LUT or output codec is needed.
    /// Inherits [`primus_tfhe_glwe::PbsParameters::encryptor`]'s signed-secret range contract.
    pub fn encryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters().encryptor(secret_key)
    }

    /// Binds a Rounded input message override without changing context defaults.
    /// Pair with the compiler's `messages.input_modulus`.
    /// Reuses the configured key domain and samplers; see
    /// [`primus_tfhe_glwe::PbsParameters::encryptor_with_message_modulus`].
    pub fn encryptor_with_message_modulus<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters()
            .encryptor_with_message_modulus(secret_key, message_modulus)
    }

    /// Binds the configured Rounded input to an external LWE public key.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>, LM>, ClientError> {
        self.parameters().public_encryptor(public_key)
    }

    /// Binds a Rounded public-key input message override without changing context defaults.
    /// Pair with the compiler's `messages.input_modulus`.
    /// Reuses the configured key domain and samplers; see
    /// [`primus_tfhe_glwe::PbsParameters::public_encryptor_with_message_modulus`].
    pub fn public_encryptor_with_message_modulus<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        message_modulus: T,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>, LM>, ClientError> {
        self.parameters()
            .public_encryptor_with_message_modulus(public_key, message_modulus)
    }

    /// Binds the configured CBS input geometry without a manually supplied codec.
    /// Use this client's `encrypt` / `encrypt_to` for both padded and MSB Boolean.
    /// Inherits [`primus_tfhe_glwe::CbsParameters::encryptor`]'s secret contract.
    pub fn cbs_encryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<CbsEncryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.cbs_parameters()
            .ok_or(TfheClientError::MissingCircuitBootstrapParameters)?
            .encryptor(secret_key)
    }

    /// Binds an external public key to the configured CBS input geometry.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn cbs_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<CbsEncryptor<'a, T, &'a LwePublicKey<T>, LM>, TfheClientError> {
        Ok(self
            .cbs_parameters()
            .ok_or(TfheClientError::MissingCircuitBootstrapParameters)?
            .public_encryptor(public_key)?)
    }

    /// Binds the configured Rounded output for ordinary PBS and ManyLUT.
    ///
    /// The decoder uses the returned LWE modulus, independently of the LUT's
    /// accumulator modulus. It copies decoding state and borrows only the secret.
    /// Factorized MVB outputs require [`Self::mvb_decryptor`] instead.
    /// Inherits [`primus_tfhe_glwe::PbsParameters::encryptor`]'s signed-secret range contract.
    pub fn pbs_decryptor<'a>(
        &self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().pbs_decryptor(secret_key)
    }

    /// Binds a Rounded PBS/ManyLUT output message override without changing context defaults.
    /// Pair with the compiler's `messages.output_modulus`.
    /// Retains the configured external key domain; see
    /// [`primus_tfhe_glwe::PbsParameters::pbs_decryptor_with_message_modulus`].
    pub fn pbs_decryptor_with_message_modulus<'a>(
        &self,
        secret_key: ExternalLweSecretKey<'a, T>,
        message_modulus: T,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters()
            .pbs_decryptor_with_message_modulus(secret_key, message_modulus)
    }

    /// Binds the configured Scaled output for factorized MVB.
    ///
    /// Uses the returned LWE modulus and retains its own decoding state.
    /// Codec validity does not establish the factor amplification, transform
    /// and return-stage noise budget.
    /// Inherits [`primus_tfhe_glwe::PbsParameters::encryptor`]'s signed-secret range contract.
    pub fn mvb_decryptor<'a>(
        &self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().mvb_decryptor(secret_key)
    }

    /// Decodes Scaled output from MVB or [`crate::Evaluator::return_ring_at_to`].
    /// `t_ring` matches the MVB program or ring candidate, independently of defaults.
    /// Inherits [`primus_tfhe_glwe::PbsParameters::ring_return_decryptor`]'s
    /// encoding, secret and joint error-budget requirements.
    pub fn ring_return_decryptor<'a>(
        &self,
        secret_key: ExternalLweSecretKey<'a, T>,
        t_ring: T,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().ring_return_decryptor(secret_key, t_ring)
    }
}

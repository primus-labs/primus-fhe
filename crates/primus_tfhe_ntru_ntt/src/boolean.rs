//! Boolean encryption and NTT-backed gate evaluation.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;

use crate::{
    Evaluator, LwePublicKey, ServerKey, TfheClientError, TfheContext, TfheEvaluationError,
};

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the explicit-modulus NTT backend.
pub type BooleanEncryptor<'a, T, Key = crate::LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::BooleanEncryptor<'a, T, LM, Key>;

/// Boolean decryptor for the explicit-modulus NTT backend.
pub type BooleanDecryptor<'a, T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::BooleanDecryptor<'a, T, LM>;

/// Boolean gate evaluator backed by NTT programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table, LM = BarrettModulus<T>> =
    primus_tfhe::BooleanEvaluator<T, LM, Evaluator<'a, T, Table, LM>>;

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates a Boolean encryptor from the configured Rounded input, requiring t=4.
    pub fn boolean_encryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
    ) -> Result<BooleanEncryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(self.encryptor(secret_key)?)?)
    }

    /// Creates a public-key Boolean encryptor from the configured input, requiring t=4.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>, LM>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor(public_key)?)
    }

    /// Creates a Boolean decryptor from the configured Rounded output, requiring t=4.
    /// Copies decoding state and borrows only the external secret.
    pub fn boolean_decryptor<'a>(
        &self,
        secret_key: &'a LweSecretKey<T>,
    ) -> Result<BooleanDecryptor<'a, T, LM>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(self.pbs_decryptor(secret_key)?)?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires configured input/output t=4; online `_to` operations reuse storage.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table, LM>, TfheEvaluationError> {
        let messages = self.parameters().messages();
        let boolean_modulus = T::ONE << primus_tfhe::BOOLEAN_PLAINTEXT_BITS;
        if messages.input_modulus != boolean_modulus || messages.output_modulus != boolean_modulus {
            return Err(TfheEvaluationError::InvalidBooleanEncoding);
        }
        let codec = RoundedCodec::try_new(
            messages.input_modulus,
            self.parameters().external_lwe().cipher_modulus(),
        )
        .map_err(crate::LookupTableError::InputEncoding)?;
        BooleanEvaluator::try_new(
            self.parameters().external_lwe_dimension(),
            self.parameters().accumulator_ntru().poly_length(),
            &codec,
            self.parameters().accumulator_ntru().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }
}

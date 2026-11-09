//! Boolean encryption and Fourier-backed gate evaluation.

use primus_encoding::RoundedCodec;
use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;
use primus_modulus::NativeModulus;

use crate::{
    Evaluator, ExternalLweSecretKey, ServerKey, TfheClientError, TfheContext, TfheEvaluationError,
};

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T, Key = crate::LweSecretKeyRef<'a, T>> =
    primus_tfhe_glwe::BooleanEncryptor<'a, T, NativeModulus<T>, Key>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> = primus_tfhe_glwe::BooleanDecryptor<'a, T, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table> =
    primus_tfhe::BooleanEvaluator<T, NativeModulus<T>, Evaluator<'a, T, Table>>;

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a Boolean encryptor from the configured Rounded input, requiring t=4.
    /// Inherits [`Self::encryptor`]'s signed-secret range contract.
    pub fn boolean_encryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<BooleanEncryptor<'a, T>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(self.encryptor(secret_key)?)?)
    }

    /// Creates a public-key Boolean encryptor from the configured input, requiring t=4.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor(public_key)?)
    }

    /// Creates a Boolean decryptor from the configured Rounded output, requiring t=4.
    /// Copies decoding state and borrows only the external secret.
    /// Inherits [`Self::pbs_decryptor`]'s signed-secret range contract.
    pub fn boolean_decryptor<'a>(
        &self,
        secret_key: ExternalLweSecretKey<'a, T>,
    ) -> Result<BooleanDecryptor<'a, T>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(self.pbs_decryptor(secret_key)?)?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires q=Q and configured input/output t=4; online `_to` operations reuse storage.
    ///
    /// Inherits [`Evaluator::try_new`]'s Fourier table identity requirement.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, TfheEvaluationError> {
        // The Boolean affine wrapper currently compiles in its external domain.
        // Reject two-domain input instead of binding LUTs at the wrong modulus.
        if self.parameters().ring_to_small_modulus_switch().is_some() {
            return Err(TfheEvaluationError::BooleanRequiresSameModulus);
        }
        let messages = self.parameters().messages();
        let boolean_modulus = T::ONE << primus_tfhe::BOOLEAN_PLAINTEXT_BITS;
        if messages.input_modulus != boolean_modulus || messages.output_modulus != boolean_modulus {
            return Err(TfheEvaluationError::InvalidBooleanEncoding);
        }
        let codec =
            RoundedCodec::try_new(messages.input_modulus, self.parameters().external_modulus())
                .map_err(crate::LookupTableError::InputEncoding)?;
        BooleanEvaluator::try_new(
            self.parameters().external_lwe_dimension(),
            self.parameters().blind_rotation_params().poly_length(),
            &codec,
            self.parameters().blind_rotation_params().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }
}

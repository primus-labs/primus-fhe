//! Server evaluation material and paired or component key generation.

use primus_reduce::RingContext;
mod circuit;
pub use circuit::CircuitBootstrapServerKey;

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweEncryptor, FourierGlweKeySwitchingKey, SecretKeyDistr};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    BlindRotationMethod, GlweKeySwitchingParameters, KeyGenerationError, PbsParameters,
    TfheContext, bootstrapping_key::FourierGlweBootstrappingKey,
    sparse::SparseGlweBootstrappingKey,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store Fourier GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BlindRotationKey<T: TorusFftValue> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(FourierGlweBootstrappingKey<T>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T, NativeModulus<T>>),
}

impl<T: TorusFftValue> BlindRotationKey<T> {
    /// Validate the selected BR layout and input domain, independently of ring KS/CBS.
    pub(crate) fn is_compatible<LM: RingContext<T>>(
        &self,
        parameters: &PbsParameters<T, LM>,
    ) -> bool {
        // Ring rows are native; the independent small-LWE q must also match.
        let (dimension, input_modulus, distribution, size, basis) = match self {
            Self::Classic(key) => (
                key.input_dimension(),
                key.input_modulus_value(),
                key.input_distribution(),
                key.size(),
                key.basis(),
            ),
            Self::Sparse(key) => (
                key.input_dimension(),
                key.controls().input_modulus_value(),
                SecretKeyDistr::FixedHammingWeightBinary {
                    hamming_weight: key.hamming_weight(),
                },
                key.controls().size(),
                key.controls().basis(),
            ),
        };
        dimension == (parameters.small_lwe().dimension())
            && input_modulus == parameters.small_lwe().cipher_modulus_value()
            && distribution == parameters.small_lwe().secret_key_distr()
            && size == parameters.blind_rotation_params().size()
            && basis == parameters.blind_rotation_params().basis()
    }
}

/// Classic or sparse evaluation keys used by a Fourier TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: TorusFftValue> {
    blind_rotation_key: BlindRotationKey<T>,
    glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Moves BR and KS material into one bundle without copying buffers.
    /// Evaluator binding checks layouts; actual secret and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation_key: BlindRotationKey<T>,
        glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            blind_rotation_key,
            glwe_key_switching_key,
        }
    }

    /// Borrows the selected classic or sparse blind-rotation material.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation_key
    }

    /// Borrows the required ring key-switching key.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &FourierGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Moves out BR and KS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, FourierGlweKeySwitchingKey<T>) {
        (self.blind_rotation_key, self.glwe_key_switching_key)
    }
}

/// Checks imported KS rows against parameters already paired with their BR domain.
/// Context setup and evaluator rebinding retain that pairing independently of the key.
pub(crate) fn check_bound_glwe_key_switching_key<T: TorusFftValue>(
    expected: &GlweKeySwitchingParameters<T>,
    key: &FourierGlweKeySwitchingKey<T>,
) -> Result<(), crate::TfheEvaluationError> {
    if key.input_dimension() != expected.input_dimension()
        || key.output_size() != expected.output_size()
        || key.basis() != expected.output().basis()
    {
        return Err(crate::TfheEvaluationError::IncompatibleGlweKeySwitchingKey);
    }
    Ok(())
}

/// Generates client and classic or sparse server keys for one Fourier context.
pub struct KeyGenerator<'a, T, Table, LM = NativeModulus<T>>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) fft: FftEngine<'a, Table>,
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Creates a key generator with reusable FFT scratch.
    pub fn new(context: &'a TfheContext<T, Table, LM>) -> Self {
        Self {
            context,
            fft: context.new_fft_engine(),
        }
    }

    /// Generates only BR material using this context's configured method and gadgets.
    /// No return or CBS key is generated. Sparse BR keeps the fixed-weight input
    /// secret and retries at most eight public maps, without falling back to classic.
    /// Each selector and dummy is encrypted independently after matching succeeds.
    ///
    /// # Correctness
    /// Independently generated components must share the actual secrets and this
    /// context's transform representation. Imported accumulator coefficients must
    /// fit the configured sampler support; ordinary FFT error remains budgeted.
    /// Sparse matching is not constant-time; see [`SparseGlweBootstrappingKey`]
    /// for the conditional-distribution and security requirements.
    ///
    /// # Errors
    /// Rejects incompatible secrets or invalid sparse geometry before consuming
    /// randomness. Sparse matching failure consumes only map randomness and returns
    /// no partial key.
    pub fn try_generate_blind_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        client_key.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation()?;
        let mut encryptor = FourierGlweEncryptor::try_new(
            client_key.glwe_secret_key(),
            self.context
                .parameters()
                .blind_rotation_params()
                .encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;
        self.generate_blind_rotation_key_with_accumulator(
            client_key,
            &mut encryptor,
            sparse_layout,
            rng,
        )
    }

    /// Generates ring KS material from the accumulator to the padded small secret.
    /// PBS order determines whether it is used before BR or when returning its result.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform requirements.
    pub fn try_generate_glwe_key_switching_key<R>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<FourierGlweKeySwitchingKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.context
            .parameters()
            .evaluation()
            .check_key_switching_parameters(key_switching)?;
        client_key.check_compatible(self.context.parameters())?;
        self.generate_glwe_key_switching_key(key_switching, client_key, rng)
    }

    /// Generates the configured BR and KS pair.
    /// Validates sparse geometry before sampling the client. Shares accumulator
    /// preparation across BR rows, then prepares the separate KS target. Sparse
    /// matching retries only public maps, keeping the same client secrets.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key`]'s noise and representation contracts.
    pub fn try_generate<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let sparse_layout = self.prepare_blind_rotation()?;
        let client_key = ClientKey::generate(self.context.parameters(), rng);
        let encryptor = FourierGlweEncryptor::try_new(
            client_key.glwe_secret_key(),
            self.context
                .parameters()
                .blind_rotation_params()
                .encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;
        let server_key =
            self.generate_server_key_with_accumulator(&client_key, encryptor, sparse_layout, rng)?;
        Ok((client_key, server_key))
    }

    /// Generates configured BR and KS material for an existing client.
    /// Checks the imported secrets before conversion or sampling; retains its input distribution.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform contracts.
    /// BR and KS errors must fit the complete PBS noise budget.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        client_key.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation()?;
        let encryptor = FourierGlweEncryptor::try_new(
            client_key.glwe_secret_key(),
            self.context
                .parameters()
                .blind_rotation_params()
                .encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;
        self.generate_server_key_with_accumulator(client_key, encryptor, sparse_layout, rng)
    }

    /// Encrypts selected BR controls after key compatibility and layout preparation.
    /// The borrowed accumulator encryption setup can also be reused by paired CBS generation.
    fn generate_blind_rotation_key_with_accumulator<R>(
        &mut self,
        client_key: &ClientKey<T>,
        encryptor: &mut FourierGlweEncryptor<'_, T>,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let blind_rotation_ggsw = parameters.blind_rotation_params();

        Ok(match sparse_layout {
            None => BlindRotationKey::Classic(FourierGlweBootstrappingKey::generate_fourier(
                client_key.small_lwe_secret_key(),
                parameters.small_lwe(),
                encryptor,
                blind_rotation_ggsw,
                &mut self.fft,
                rng,
            )),
            Some(layout) => BlindRotationKey::Sparse({
                let prepared = self.prepare_sparse_map(client_key, layout, rng)?;
                self.generate_sparse_bootstrapping_key_with_accumulator(prepared, encryptor, rng)
            }),
        })
    }

    /// Consumes the accepted accumulator encryption setup for BR, then releases it before
    /// allocating KS rows. The caller established client compatibility by sampling or
    /// validation and prepared exact products for the accepted target.
    fn generate_server_key_with_accumulator<R>(
        &mut self,
        client_key: &ClientKey<T>,
        mut encryptor: FourierGlweEncryptor<'_, T>,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let blind_rotation_key = self.generate_blind_rotation_key_with_accumulator(
            client_key,
            &mut encryptor,
            sparse_layout,
            rng,
        )?;
        drop(encryptor);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(
            self.context.parameters().glwe_key_switching(),
            client_key,
            rng,
        )?;
        Ok(ServerKey {
            blind_rotation_key,
            glwe_key_switching_key,
        })
    }

    /// Generates after the setup bundle has passed compatibility checks.
    fn generate_glwe_key_switching_key<R>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<FourierGlweKeySwitchingKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let padded_small_glwe_secret_key = client_key.padded_small_glwe_secret_key(parameters);
        let mut target = FourierGlweEncryptor::try_new(
            &padded_small_glwe_secret_key,
            key_switching.output().encryption_parameters(),
        )
        .map_err(crate::error::glwe_encryption_error)?;

        Ok(FourierGlweKeySwitchingKey::generate(
            client_key.glwe_secret_key(),
            &mut target,
            key_switching,
            &mut self.fft,
            rng,
        ))
    }

    /// Checks the selected BR capability and sparse geometry before sampling secrets or rows.
    /// `None` denotes classic BR; matching for sparse BR later keeps the same secret.
    fn prepare_blind_rotation(
        &self,
    ) -> Result<Option<crate::sparse::SparseKeyLayout>, KeyGenerationError> {
        Ok(match self.context.parameters().blind_rotation_method() {
            BlindRotationMethod::Classic => None,
            BlindRotationMethod::Block => {
                return Err(KeyGenerationError::UnsupportedBlindRotationMethod(
                    BlindRotationMethod::Block,
                ));
            }
            BlindRotationMethod::Sparse {
                copy_count,
                bucket_count,
            } => Some(self.prepare_sparse_layout(copy_count, bucket_count)?),
        })
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Generates paired client and BR/KS server keys using this context's choices.
    /// Inherits [`KeyGenerator::try_generate`]'s contracts.
    pub fn try_generate_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate(rng)
    }

    /// Generates configured server material for independently generated client secrets.
    /// Inherits [`KeyGenerator::try_generate_server_key`]'s contracts.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_server_key(client_key, rng)
    }
}

//! Server evaluation material and paired or component key generation.

mod circuit;
pub use circuit::CircuitBootstrapServerKey;

use primus_glwe::{
    GgswParameters, NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey, NttGlweSecretKey,
    SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_reduce::{Modulus, RingContext};
use primus_tfhe_glwe::ClientKey;

use crate::{
    BlindRotationMethod, KeyGenerationError, PbsParameters, TfheContext,
    block::BlockGlweBootstrappingKey, bootstrapping_key::NttGlweBootstrappingKey,
    sparse::SparseGlweBootstrappingKey,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store NTT GGSWs; grouped keys store coefficient GGSWs
/// with public bucket or block geometry. All target the same accumulator secret
/// and use the small-LWE input.
pub enum BlindRotationKey<T: FheUint> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(NttGlweBootstrappingKey<T>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T, BarrettModulus<T>>),
    /// Contiguous block-binary controls with an independent dummy per block.
    Block(BlockGlweBootstrappingKey<T, BarrettModulus<T>>),
}

/// Checked setup geometry, before client sampling or row allocation.
/// This temporary choice carries no control ciphertexts or private assignments.
enum BlindRotationLayout {
    Classic,
    Sparse(crate::sparse::SparseKeyLayout),
    Block(crate::block::BlockKeyLayout),
}

impl BlindRotationLayout {
    fn try_new<T: FheUint>(
        dimension: usize,
        distribution: SecretKeyDistr,
        parameters: &GgswParameters<T, BarrettModulus<T>>,
        method: BlindRotationMethod,
    ) -> Result<Self, KeyGenerationError> {
        Ok(match method {
            BlindRotationMethod::Classic => Self::Classic,
            BlindRotationMethod::Sparse {
                copy_count,
                bucket_count,
            } => Self::Sparse(crate::sparse::SparseKeyLayout::try_new(
                dimension,
                distribution,
                parameters,
                copy_count,
                bucket_count,
            )?),
            BlindRotationMethod::Block => Self::Block(crate::block::BlockKeyLayout::try_new(
                dimension,
                distribution,
                parameters,
            )?),
        })
    }
}

impl<T: FheUint> BlindRotationKey<T> {
    /// Generates BR material independently of PBS return parameters.
    /// Input q and control distribution come from the owning LWE secret;
    /// `parameters` describes the independent target ring and GGSW rows.
    /// Sparse generation preserves the fixed secret and retries at most eight maps.
    ///
    /// # Correctness
    /// The target secret must use `table`'s transform representation. Signed
    /// coefficients inherit [`NttGlweSecretKey::from_coeff_secret_key`]'s range
    /// requirements. Sparse conditional-distribution/security requirements are
    /// those of [`SparseGlweBootstrappingKey`].
    ///
    /// # Errors
    /// Rejects invalid sparse/block geometry or control distributions before
    /// sampling. Block imports additionally check 0/1 and at-most-one per block.
    /// Sparse support/matching errors return no partial key.
    ///
    /// # Panics
    /// Panics on invalid classic secret coefficients/distribution, target key,
    /// table or workspace mismatch, allocation overflow, or unrepresentable 2N.
    pub fn try_generate<Table, R>(
        input: &LweSecretKey<T>,
        output: &NttGlweSecretKey<T>,
        parameters: &GgswParameters<T, BarrettModulus<T>>,
        method: BlindRotationMethod,
        table: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Result<Self, KeyGenerationError>
    where
        Table: MonomialNttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let layout =
            BlindRotationLayout::try_new(input.dimension(), input.distr(), parameters, method)?;
        // A raw owning secret has not passed the context's ClientKey boundary.
        // Only this Block branch scans it here; prepared context generation uses
        // the already validated path below, avoiding a second full secret scan.
        if let BlindRotationLayout::Block(layout) = layout {
            workspace.resize(parameters.size());
            return Ok(Self::Block(crate::block::generate_with_layout(
                input, layout, output, parameters, table, rng, workspace,
            )?));
        }
        Self::generate_with_layout(input, output, parameters, layout, table, rng, workspace)
    }

    /// Shares component generation with context-based keygen after public geometry checks.
    fn generate_with_layout<Table, R>(
        input: &LweSecretKey<T>,
        output: &NttGlweSecretKey<T>,
        parameters: &GgswParameters<T, BarrettModulus<T>>,
        layout: BlindRotationLayout,
        table: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Result<Self, KeyGenerationError>
    where
        Table: MonomialNttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        workspace.resize(parameters.size());
        Ok(match layout {
            BlindRotationLayout::Classic => Self::Classic(NttGlweBootstrappingKey::generate_ntt(
                input, output, parameters, table, rng, workspace,
            )),
            BlindRotationLayout::Sparse(layout) => {
                Self::Sparse(crate::sparse::generate_with_layout(
                    input, layout, output, parameters, table, rng, workspace,
                )?)
            }
            BlindRotationLayout::Block(layout) => {
                Self::Block(crate::block::generate_validated_with_layout(
                    input, layout, output, parameters, table, rng, workspace,
                )?)
            }
        })
    }

    /// Validate the selected BR layout and input domain, independently of ring KS/CBS.
    pub(crate) fn is_compatible<LM: RingContext<T>>(
        &self,
        parameters: &PbsParameters<T, LM>,
    ) -> bool {
        let (dimension, input_modulus, size, basis, cipher_modulus) = match self {
            Self::Classic(key) => {
                if key.input_distribution() != parameters.small_lwe().secret_key_distr() {
                    return false;
                }
                (
                    key.input_dimension(),
                    key.input_modulus_value(),
                    key.size(),
                    key.basis(),
                    key.cipher_modulus(),
                )
            }
            Self::Sparse(key) => {
                if parameters.small_lwe().secret_key_distr()
                    != (SecretKeyDistr::FixedHammingWeightBinary {
                        hamming_weight: key.hamming_weight(),
                    })
                {
                    return false;
                }
                (
                    key.input_dimension(),
                    key.controls().input_modulus_value(),
                    key.controls().size(),
                    key.controls().basis(),
                    key.controls().cipher_modulus(),
                )
            }
            Self::Block(key) => {
                if parameters.small_lwe().secret_key_distr()
                    != (SecretKeyDistr::BlockBinary {
                        block_size: key.block_size(),
                    })
                {
                    return false;
                }
                let controls = key.controls();
                (
                    controls.input_dimension(),
                    controls.input_modulus_value(),
                    controls.size(),
                    controls.basis(),
                    controls.cipher_modulus(),
                )
            }
        };
        dimension == (parameters.small_lwe().dimension())
            && input_modulus == parameters.small_lwe().cipher_modulus_value()
            && size == parameters.blind_rotation_params().size()
            && basis == parameters.blind_rotation_params().basis()
            && cipher_modulus == parameters.ring_modulus().explicit_value()
    }
}

/// Classic, sparse or block evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: FheUint> {
    blind_rotation_key: BlindRotationKey<T>,
    glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    /// Moves BR and KS material into one bundle without copying buffers.
    /// Evaluator binding checks layouts; actual secret and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation_key: BlindRotationKey<T>,
        glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            blind_rotation_key,
            glwe_key_switching_key,
        }
    }

    /// Borrows the selected blind-rotation material.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation_key
    }

    /// Borrows the required ring key-switching key.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &NttGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Moves out BR and KS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, NttGlweKeySwitchingKey<T>) {
        (self.blind_rotation_key, self.glwe_key_switching_key)
    }
}

/// Checks imported KS rows against parameters already paired with their BR domain.
/// Context setup and evaluator rebinding retain that pairing independently of the key.
pub(crate) fn check_bound_glwe_key_switching_key<T: FheUint>(
    expected: &crate::GlweKeySwitchingParameters<T>,
    key: &NttGlweKeySwitchingKey<T>,
) -> Result<(), crate::TfheEvaluationError> {
    if key.input_dimension() != expected.input_dimension()
        || key.output_size() != expected.output_size()
        || key.basis() != expected.output().basis()
    {
        return Err(crate::TfheEvaluationError::IncompatibleGlweKeySwitchingKey);
    }
    Ok(())
}

/// Generates client and server keys for one NTT context.
pub struct KeyGenerator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) gadget: NttGlweGadgetEncryptWorkspace<T>,
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates a key generator with reusable NTT gadget scratch.
    pub fn new(context: &'a TfheContext<T, Table, LM>) -> Self {
        let parameters = context.parameters().blind_rotation_params();
        Self {
            context,
            gadget: NttGlweGadgetEncryptWorkspace::new(parameters.size()),
        }
    }

    /// Generates only BR material using this context's configured method and gadgets.
    /// No return or CBS key is generated. Sparse BR keeps the fixed-weight input
    /// secret and retries at most eight public maps, without falling back to classic.
    /// Each selector and dummy is encrypted independently after matching succeeds.
    ///
    /// # Correctness
    /// Independently generated components must share the actual secrets and this
    /// context's transform representation. Imported accumulator coefficients inherit
    /// [`NttGlweSecretKey::from_coeff_secret_key`]'s numerical requirements.
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
        let layout = self.prepare_blind_rotation()?;
        let transformed = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        self.generate_blind_rotation_key_with_main(client_key, &transformed, layout, rng)
    }

    /// Generates ring KS material from the accumulator to the padded small secret.
    /// PBS order determines whether it is used before BR or when returning its result.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform requirements.
    pub fn try_generate_glwe_key_switching_key<R>(
        &mut self,
        key_switching: &crate::GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<NttGlweKeySwitchingKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.context
            .parameters()
            .evaluation()
            .check_key_switching_parameters(key_switching)?;
        client_key.check_compatible(self.context.parameters())?;
        Ok(self.generate_glwe_key_switching_key(key_switching, client_key, rng))
    }

    /// Generates the configured BR and KS pair.
    /// Validates sparse geometry before sampling the client. Reuses prepared KS
    /// state and retries only public maps, keeping the same client secrets.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key`]'s noise and representation contracts.
    pub fn try_generate<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        let layout = self.prepare_blind_rotation()?;
        let client_key = ClientKey::generate(self.context.parameters(), rng);
        let transformed = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        let server_key =
            self.generate_server_key_with_main(&client_key, transformed, layout, rng)?;
        Ok((client_key, server_key))
    }

    /// Generates configured BR and KS material for an existing client.
    /// Checks the imported secrets before conversion or sampling; retains its input distribution.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform contracts.
    /// BR and KS errors must fit the complete PBS noise budget.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        client_key.check_compatible(self.context.parameters())?;
        let layout = self.prepare_blind_rotation()?;
        let transformed = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        self.generate_server_key_with_main(client_key, transformed, layout, rng)
    }

    /// Encrypts selected BR controls after key compatibility and layout preparation.
    /// The borrowed accumulator representation can also be reused by paired CBS generation.
    fn generate_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: &NttGlweSecretKey<T>,
        layout: BlindRotationLayout,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        let parameters = self.context.parameters();
        BlindRotationKey::generate_with_layout(
            client_key.small_lwe_secret_key(),
            main_glwe_secret_key,
            parameters.blind_rotation_params(),
            layout,
            self.context.table(),
            rng,
            &mut self.gadget,
        )
    }

    /// Consumes the accepted accumulator transform for BR, then releases it before
    /// allocating KS rows. The caller established client compatibility by sampling or
    /// validation and prepared this transform with the context's table.
    fn generate_server_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: NttGlweSecretKey<T>,
        layout: BlindRotationLayout,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let blind_rotation_key = self.generate_blind_rotation_key_with_main(
            client_key,
            &main_glwe_secret_key,
            layout,
            rng,
        )?;
        drop(main_glwe_secret_key);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(
            self.context.parameters().glwe_key_switching(),
            client_key,
            rng,
        );
        Ok(ServerKey {
            blind_rotation_key,
            glwe_key_switching_key,
        })
    }

    /// Generates after the setup bundle has passed compatibility checks.
    fn generate_glwe_key_switching_key<R>(
        &mut self,
        key_switching: &crate::GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> NttGlweKeySwitchingKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let padded_small_glwe_secret_key = client_key.padded_small_glwe_secret_key(parameters);
        let padded_small_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            &padded_small_glwe_secret_key,
            self.context.table(),
        );
        self.gadget.resize(key_switching.output_size());
        NttGlweKeySwitchingKey::generate(
            client_key.glwe_secret_key(),
            &padded_small_glwe_secret_key,
            key_switching,
            self.context.table(),
            rng,
            &mut self.gadget,
        )
    }

    /// Checks the selected public geometry before sampling secrets or key rows.
    /// Sparse matching later retains the fixed client secret; Block uses no map.
    fn prepare_blind_rotation(&self) -> Result<BlindRotationLayout, KeyGenerationError> {
        let parameters = self.context.parameters();
        BlindRotationLayout::try_new(
            parameters.small_lwe().dimension().get(),
            parameters.small_lwe().secret_key_distr(),
            parameters.blind_rotation_params(),
            parameters.blind_rotation_method(),
        )
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
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

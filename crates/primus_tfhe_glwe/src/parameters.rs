//! Shared blind-rotation domains and complete GLWE PBS parameters.

mod cbs;
mod evaluation;
pub use cbs::CbsParameters;
pub use evaluation::PbsEvaluationParameters;

use std::sync::Arc;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlevParameterError, GlweEncryptionParameters, GlweSize};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_reduce::{ModulusSwitch, RingContext};
use primus_tfhe::{BlindRotationMethod, ModulusConfig, ModulusConfigError, PbsMessageConfig};

use crate::{
    GadgetEncryptionConfig, GgswParameters, GlevParameters, GlweKeySwitchingParameters, PbsConfig,
    SecretKeyDistr, TfheParameterError,
};

/// Execution order of programmable bootstrapping and key switching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbsOrder {
    /// Blind rotation is followed by a GLWE key switch and compact sample
    /// extraction and Q→q rounding back to the small LWE key.
    BootstrapKeyswitch,
    /// A GLWE key switch and compact sample extraction first produce a small
    /// LWE ciphertext at Q, rescaled to q before BR. External input and returned
    /// full extraction use the ring secret at Q.
    KeyswitchBootstrap,
}

/// Prepared GLWE PBS domain, ring KS and default message choices.
/// CBS shares the same KS material for input preparation or later LWE returns.
/// Small and ring secrets remain independent.
#[derive(Clone)]
pub struct PbsParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    messages: PbsMessageConfig<T>,
    small_lwe: LweEncryptionParameters<T, LM>,
    blind_rotation_method: BlindRotationMethod,
    evaluation: PbsEvaluationParameters<T, M>,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Prepares the common domain and ring KS from numerical choices.
    /// Checks binary/ternary controls, n <= kN and representability of 2N before
    /// returning the prepared state. Input and accumulator secrets are independent.
    /// The Block method additionally requires a block-binary control distribution.
    pub fn try_from_config(config: PbsConfig<T, M, LM>) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        let small_lwe = LweEncryptionParameters::try_from(config.small_lwe)
            .map_err(TfheParameterError::InputParameters)?;

        let distribution = small_lwe.secret_key_distr();
        if !distribution.is_binary() && !distribution.is_ternary() {
            return Err(TfheParameterError::UnsupportedInputLweSecretKey);
        }
        if config.method == BlindRotationMethod::Block
            && !matches!(distribution, SecretKeyDistr::BlockBinary { .. })
        {
            return Err(TfheParameterError::InvalidBlockSecretDistribution);
        }

        let bsk_size = GlweSize::try_new(config.bsk_dimension, config.bsk_poly_length)
            .map_err(TfheParameterError::AccumulatorLayout)?;
        let blind_rotation_ggsw = GgswParameters::try_new(
            bsk_size,
            M::try_from(config.ring_modulus).map_err(TfheParameterError::RingModulus)?,
            config.bsk_secret_distr,
            config.bsk_gadget.decomposition,
            config.bsk_gadget.noise_standard_deviation,
        )
        .map_err(|error| match error {
            GlevParameterError::Encryption(source) => {
                TfheParameterError::AccumulatorParameters(source)
            }
            source => TfheParameterError::BootstrappingParameters(source),
        })?;

        let capacity = LweDimension::from(blind_rotation_ggsw.glwe_size());
        if small_lwe.dimension() > capacity {
            return Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension().get(),
                capacity: capacity.get(),
            });
        }
        if T::try_from(blind_rotation_ggsw.poly_length().get() * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }

        let key_switching_params = Self::derive_glwe_key_switching(
            &small_lwe,
            &blind_rotation_ggsw,
            config.key_switching,
        )?;
        let ring_modulus = blind_rotation_ggsw.cipher_modulus();
        let ring_to_small = (ring_modulus.explicit_value() != small_lwe.cipher_modulus_value())
            .then(|| ModulusSwitch::new(ring_modulus, small_lwe.cipher_modulus()));
        Ok(Self {
            evaluation: PbsEvaluationParameters {
                small_dimension: small_lwe.dimension(),
                small_modulus: small_lwe.cipher_modulus_value(),
                small_secret_distr: small_lwe.secret_key_distr(),
                ring_to_small,
                pbs_order: config.order,
                blind_rotation_params: blind_rotation_ggsw,
                key_switching_params,
            },
            small_lwe,
            blind_rotation_method: config.method,
            messages: config.messages,
        })
    }

    /// Prepares ring KS targeting the padded small secret, reusing the checked BR domain.
    /// Used for either PBS order or CBS input preparation; no BR sampler is rebuilt.
    pub fn try_key_switching_parameters(
        &self,
        config: GadgetEncryptionConfig,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        Self::derive_glwe_key_switching(self.small_lwe(), self.blind_rotation_params(), config)
    }

    /// Pads the already validated small secret to whole ring components.
    /// Since n <= kN, the derived layout fits within the accumulator; its
    /// modulus is inherited, while the KS basis and noise are independent.
    /// The target encrypts gadget rows and needs no ordinary plaintext codec.
    fn derive_glwe_key_switching(
        small_lwe: &LweEncryptionParameters<T, LM>,
        accumulator: &GgswParameters<T, M>,
        key_switching: GadgetEncryptionConfig,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        let basis = ApproxSignedBasis::try_from((
            key_switching.decomposition,
            accumulator.cipher_modulus().explicit_value(),
        ))
        .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        let output_dimension = small_lwe
            .dimension()
            .get()
            .div_ceil(accumulator.poly_length().get());
        let output_size = GlweSize::new(
            GlweDimension::new(output_dimension),
            accumulator.poly_length(),
        );
        // The small-secret distribution and length are already checked; the
        // independent KS noise must be validated before preparing its sampler.
        let inner = GlweEncryptionParameters::try_new(
            accumulator.cipher_modulus(),
            small_lwe.secret_key_distr(),
            key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        // Only the logical LWE prefix follows the sampler's distribution. Its
        // public zero tail completes ring components and need not complete blocks.
        let output = GlevParameters::try_from_padded_lwe_parts(
            output_size,
            small_lwe.dimension(),
            Arc::new(inner),
            basis,
        )
        .map_err(TfheParameterError::KeySwitchingParameters)?;
        GlweKeySwitchingParameters::try_new(accumulator.dimension(), output)
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))
    }

    /// Borrows the prepared Q→q conversion after ring KS and compact extraction.
    /// `None` means equal moduli: callers should skip the entire conversion pass.
    /// Rounding acts on ciphertext coefficients, not the decrypted phase.
    #[must_use]
    pub fn ring_to_small_modulus_switch(&self) -> Option<&ModulusSwitch<T>> {
        self.evaluation.ring_to_small_modulus_switch()
    }

    /// Returns the small LWE sampling domain used by BR controls.
    #[must_use]
    #[inline]
    pub fn small_lwe(&self) -> &LweEncryptionParameters<T, LM> {
        &self.small_lwe
    }

    /// Returns the accumulator ring and BR GGSW decomposition.
    #[must_use]
    #[inline]
    pub fn blind_rotation_params(&self) -> &GgswParameters<T, M> {
        self.evaluation.blind_rotation_params()
    }

    /// Returns the selected BR material-generation algorithm.
    #[must_use]
    pub fn blind_rotation_method(&self) -> BlindRotationMethod {
        self.blind_rotation_method
    }

    /// Returns the order that determines the external input role.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.evaluation.pbs_order()
    }

    /// Returns the client-visible LWE dimension for the selected input role.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        self.evaluation.external_lwe_dimension()
    }

    /// Returns the accumulator and ring evaluation-key modulus Q.
    #[must_use]
    #[inline]
    pub fn ring_modulus(&self) -> M {
        self.evaluation.ring_modulus()
    }

    /// Returns the external ciphertext modulus for the selected order.
    /// BR→KS uses q; KS→BR uses Q. `None` denotes the native torus.
    #[must_use]
    pub fn external_modulus_value(&self) -> Option<T> {
        self.evaluation.external_modulus_value()
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<Self> for PbsParameters<T, M, LM> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Borrows ring KS shared by PBS and downstream CBS LWE returns.
    #[must_use]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, M> {
        self.evaluation.glwe_key_switching()
    }

    /// Returns default independently selectable input/output message moduli.
    #[must_use]
    pub fn messages(&self) -> PbsMessageConfig<T> {
        self.messages
    }
}

// Equal reducer types can represent different values. This accessor selects the
// external role, while mixed-reducer callers use the explicit q/Q accessors.
impl<T: FheUint, M: RingContext<T>> PbsParameters<T, M> {
    /// Returns the external LWE modulus selected by the PBS order.
    #[must_use]
    pub fn external_modulus(&self) -> M {
        match self.pbs_order() {
            PbsOrder::BootstrapKeyswitch => self.small_lwe().cipher_modulus(),
            PbsOrder::KeyswitchBootstrap => self.ring_modulus(),
        }
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Borrows the prepared server-side state, without the client reducer or codecs.
    #[must_use]
    pub fn evaluation(&self) -> &PbsEvaluationParameters<T, M> {
        &self.evaluation
    }
}

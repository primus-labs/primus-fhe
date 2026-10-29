//! Shared blind-rotation domains and complete NTRU PBS parameters.

mod cbs;
pub use cbs::CbsParameters;

use std::sync::Arc;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lwe::{LweDimension, LweEncryptionParameters, LweKeySwitchingParameters};
use primus_ntru::{NlevParameters, NtruEncryptionParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, PbsMessageConfig, rotation::RotationModulusSwitch};

use crate::{GadgetEncryptionConfig, TfheParameterError};

/// Prepared NTRU PBS domain, f→s return KS and message choices.
/// Ordinary LWE-output PBS requires Q→q conversion and f→s key switching.
/// CBS shares the return material for subsequent operations on its ring output.
/// Input and ring secrets remain independent.
#[derive(Clone)]
pub struct PbsParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    external_lwe: LweEncryptionParameters<T, LM>,
    blind_rotation: NlevParameters<T, M>,
    rotation_modulus_switch: RotationModulusSwitch<T>,
    blind_rotation_method: BlindRotationMethod,
    key_switching: LweKeySwitchingParameters<T, LM>,
    messages: PbsMessageConfig<T>,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Prepares the common q/Q domain and return state from numerical choices.
    /// External controls must be binary or ternary and 2N must fit T. Ring
    /// invertibility, sparse-map feasibility and the joint noise budget are separate.
    /// The Block method currently requires an at-most-one block-binary distribution.
    pub fn try_from_config(config: crate::PbsConfig<T, M, LM>) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let external_lwe = LweEncryptionParameters::try_from(config.external_lwe)
            .map_err(TfheParameterError::InputParameters)?;
        let distr = external_lwe.secret_key_distr();
        if !(distr.is_binary() || distr.is_ternary()) {
            return Err(TfheParameterError::UnsupportedClientSecretKeyDistribution);
        }
        if config.method == BlindRotationMethod::Block
            && !matches!(
                distr,
                SecretKeyDistr::BlockBinary {
                    occupancy: primus_ntru::BlockOccupancy::AtMostOne,
                    ..
                }
            )
        {
            return Err(TfheParameterError::InvalidBlockSecretDistribution);
        }
        let modulus =
            M::try_from(config.ring_modulus).map_err(TfheParameterError::AccumulatorModulus)?;
        let blind_rotation = prepare_blind_rotation(
            config.bsk_poly_length,
            modulus,
            config.bsk_secret_distr,
            config.bsk_gadget,
        )?;
        let two_n = 2 * blind_rotation.poly_length().get();
        T::try_from(two_n).map_err(|_| TfheParameterError::RotationDomainTooLarge)?;
        let rotation_modulus_switch =
            RotationModulusSwitch::new(external_lwe.cipher_modulus(), two_n, 1);
        let basis = ApproxSignedBasis::try_from((
            config.key_switching.decomposition,
            external_lwe.cipher_modulus_value(),
        ))
        .map_err(TfheParameterError::KeySwitchingParameters)?;
        let output = LweEncryptionParameters::try_new(
            external_lwe.dimension(),
            external_lwe.cipher_modulus(),
            external_lwe.secret_key_distr(),
            config.key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        let key_switching = LweKeySwitchingParameters::try_new(output, basis)
            .map_err(TfheParameterError::KeySwitchingEncryption)?;
        Ok(Self {
            external_lwe,
            blind_rotation,
            rotation_modulus_switch,
            blind_rotation_method: config.method,
            key_switching,
            messages: config.messages,
        })
    }

    /// Returns the algorithm selected for generating BR material.
    #[must_use]
    pub fn blind_rotation_method(&self) -> BlindRotationMethod {
        self.blind_rotation_method
    }

    /// Returns the rotation modulus switch prepared for ordinary PBS.
    #[doc(hidden)]
    #[must_use]
    pub fn rotation_modulus_switch(&self) -> &RotationModulusSwitch<T> {
        &self.rotation_modulus_switch
    }

    /// Returns the external LWE domain and fresh-encryption samplers at q.
    #[must_use]
    #[inline]
    pub fn external_lwe(&self) -> &LweEncryptionParameters<T, LM> {
        &self.external_lwe
    }

    /// Returns the shared parameters of the NLev initializer and NGSW controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation(&self) -> &NlevParameters<T, M> {
        &self.blind_rotation
    }

    /// Borrows the accumulator ring and samplers owned by the BR gadget.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru(&self) -> &NtruEncryptionParameters<T, M> {
        self.blind_rotation().encryption_parameters()
    }

    /// Returns the dimension of external LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        self.external_lwe().dimension()
    }

    /// Returns the accumulator polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.blind_rotation().poly_length()
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<Self> for PbsParameters<T, M, LM> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Borrows f→s return material at q.
    #[must_use]
    pub fn key_switching(&self) -> &LweKeySwitchingParameters<T, LM> {
        &self.key_switching
    }

    /// Returns default independently selectable input/output message moduli.
    #[must_use]
    pub fn messages(&self) -> PbsMessageConfig<T> {
        self.messages
    }
}

/// Prepares shared NLev/NGSW state for numerical blind-rotation configs.
fn prepare_blind_rotation<T: FheUint, M: RingContext<T>>(
    poly_length: PolyLength,
    modulus: M,
    secret: SecretKeyDistr,
    gadget: GadgetEncryptionConfig,
) -> Result<NlevParameters<T, M>, TfheParameterError> {
    let accumulator = NtruEncryptionParameters::try_new(
        poly_length,
        modulus,
        secret,
        gadget.noise_standard_deviation,
    )
    .map_err(TfheParameterError::AccumulatorParameters)?;
    let basis =
        ApproxSignedBasis::try_from((gadget.decomposition, accumulator.cipher_modulus_value()))
            .map_err(|source| TfheParameterError::BootstrappingParameters(source.into()))?;
    NlevParameters::try_from_parts(Arc::new(accumulator), basis)
        .map_err(TfheParameterError::BootstrappingParameters)
}

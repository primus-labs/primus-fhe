//! Numerical LWE descriptions before preparing samplers.

use primus_integer::FheUint;
use primus_modulus::{ModulusConfig, ModulusConfigError};
use primus_reduce::{Modulus, RingContext};

use crate::{LweDimension, LweEncryptionParameters, LweParameterError, SecretKeyDistr};

/// Numerical LWE choices, with no prepared distribution or message codec.
/// Convert with `LweEncryptionParameters::try_from(config)` to validate the
/// modulus representation and prepare sampling state. This uses the same secret
/// and noise checks as [`LweEncryptionParameters::try_new`].
///
/// # Example
///
/// ```
/// use primus_lwe::{LweConfig, LweDimension, LweEncryptionParameters, SecretKeyDistr};
/// use primus_modulus::{ModulusConfig, NativeModulus};
///
/// // Small illustrative parameters, not a security recommendation.
/// const CONFIG: LweConfig<NativeModulus<u64>> = LweConfig {
///     dimension: LweDimension::new(64),
///     cipher_modulus: ModulusConfig::Native,
///     secret_key_distr: SecretKeyDistr::UniformBinary,
///     noise_standard_deviation: 0.7,
/// };
/// let parameters = LweEncryptionParameters::try_from(CONFIG)?;
/// # Ok::<(), primus_lwe::LweConfigError>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct LweConfig<M: Modulus> {
    /// Secret dimension.
    pub dimension: LweDimension,
    /// Ciphertext modulus and its reduction representation.
    pub cipher_modulus: ModulusConfig<M>,
    /// Secret coefficient distribution, including a public fixed weight if used.
    pub secret_key_distr: SecretKeyDistr,
    /// Fresh encryption noise standard deviation, in coefficient units.
    pub noise_standard_deviation: f64,
}

/// Failure to prepare the modulus or sampling state of an LWE description.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LweConfigError {
    /// The modulus does not fit the selected reducer.
    #[error(transparent)]
    Modulus(#[from] ModulusConfigError),
    /// The secret support or noise sampler is invalid.
    #[error(transparent)]
    Parameters(#[from] LweParameterError),
}

impl<T, M> TryFrom<LweConfig<M>> for LweEncryptionParameters<T, M>
where
    T: FheUint,
    M: RingContext<T> + TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
{
    type Error = LweConfigError;

    fn try_from(config: LweConfig<M>) -> Result<Self, Self::Error> {
        Ok(Self::try_new(
            config.dimension,
            M::try_from(config.cipher_modulus)?,
            config.secret_key_distr,
            config.noise_standard_deviation,
        )?)
    }
}

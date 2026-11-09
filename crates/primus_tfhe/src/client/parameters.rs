use primus_distr::DiscreteGaussian;
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use super::ClientError;

/// Parameters for rounded messages in one external LWE domain.
///
/// Construction reuses the mask sampler derived from the codec's ciphertext modulus.
/// Families select the active secret dimension and fresh-encryption noise once.
/// The small codec state is copied; only the noise sampler is borrowed. This
/// value contains no family key, PBS order or transform-specific state.
///
/// # Correctness
///
/// Secret coefficients inherit [`primus_lwe::LweSecretKeyRef`]'s range contracts.
/// Noise must fit the message and programmable-bootstrap input budgets;
/// constructor checks establish sampler compatibility, not a noise budget.
#[derive(Clone, Copy)]
pub struct LweClientParameters<'a, T: FheUint, M: RingContext<T>> {
    dimension: LweDimension,
    codec: RoundedCodec<T, M>,
    uniform: Uniform<T>,
    noise: &'a DiscreteGaussian<T>,
}

impl<'a, T: FheUint, M: RingContext<T>> LweClientParameters<'a, T, M> {
    /// Creates [`LweClientParameters`] from one validated LWE parameter set.
    #[must_use]
    pub fn new(parameters: &'a LweParameters<T, M>) -> Self {
        let codec = parameters.plaintext_codec();
        Self {
            dimension: parameters.dimension(),
            codec: *codec,
            uniform: parameters.cipher_modulus_uniform_distr(),
            noise: parameters.noise_distribution(),
        }
    }

    /// Binds an external dimension, message codec and prepared noise sampler.
    ///
    /// Rejects noise using another ciphertext modulus. The family selects the
    /// dimension and noise for its active external secret; the codec determines
    /// the message space, independently of key generation. No sampler table is built.
    pub fn try_from_parts(
        dimension: LweDimension,
        codec: &RoundedCodec<T, M>,
        noise: &'a DiscreteGaussian<T>,
    ) -> Result<Self, ClientError> {
        if noise.modulus_minus_one() != codec.ciphertext_modulus().minus_one() {
            return Err(ClientError::NoiseModulusMismatch);
        }
        Ok(Self {
            dimension,
            codec: *codec,
            uniform: codec.ciphertext_modulus().uniform_distribution(),
            noise,
        })
    }

    /// Returns the external LWE dimension.
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Returns the rounded message codec and ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn codec(&self) -> &RoundedCodec<T, M> {
        &self.codec
    }

    /// Returns the prepared mask sampler derived from the ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn uniform(&self) -> Uniform<T> {
        self.uniform
    }

    /// Returns the selected fresh-encryption noise sampler.
    #[must_use]
    #[inline]
    pub fn noise(&self) -> &'a DiscreteGaussian<T> {
        self.noise
    }
}

//! Ring and sampling state shared by ordinary and gadget NTRU parameters.

use super::NtruParameterError;
use crate::SecretKeyDistr;
use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_shape::PolyLength;

/// Prepared NTRU ring, secret sampler and coefficient-unit encryption noise.
///
/// The single-polynomial layout fixes the complete secret length N, so weight
/// and modulus support are checked here. This does not establish invertibility:
/// NTT/Fourier key generation retains its rejection and numerical-stability checks.
/// Ordinary and gadget parameters share this immutable state through `Arc`;
/// cloning this value directly still copies its sampler tables.
#[derive(Clone)]
pub struct NtruEncryptionParameters<T: FheUint, M: RingContext<T>> {
    poly_length: PolyLength,
    cipher_modulus: M,
    secret_key_sampler: SecretKeySampler<T>,
    noise_distribution: DiscreteGaussian<T>,
}

impl<T: FheUint, M: RingContext<T>> NtruEncryptionParameters<T, M> {
    /// Creates a [`NtruEncryptionParameters`] without a message codec.
    ///
    /// # Panics
    /// Panics on the secret/noise sampler errors of [`Self::try_new`].
    #[must_use]
    pub fn new(
        poly_length: PolyLength,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            poly_length,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid NTRU sampling parameters")
    }

    /// Checks coefficient noise, secret support at q and fixed weight over N.
    /// Noise serves both ordinary and gadget-row encryption; prepare separate
    /// states when those roles require different noise. No mask sampler is used.
    pub fn try_new(
        poly_length: PolyLength,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, NtruParameterError> {
        let modulus_minus_one = cipher_modulus.minus_one();
        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, modulus_minus_one)?;
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(poly_length.get())?;
        secret_key_sampler.validate_modulus(modulus_minus_one)?;
        Ok(Self {
            poly_length,
            cipher_modulus,
            secret_key_sampler,
            noise_distribution,
        })
    }

    /// Returns the ring length and full secret length N.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Returns the ciphertext modulus context.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the explicit modulus, or None for the native modulus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.cipher_modulus.explicit_value()
    }

    /// Returns the proposal distribution before backend rejection sampling.
    #[must_use]
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_sampler.distr()
    }

    /// Returns the prepared coefficient-key sampler.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.secret_key_sampler
    }

    /// Returns coefficient-unit encryption noise at the ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }
}

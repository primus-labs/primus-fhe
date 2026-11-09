//! Immutable layout and sampling precomputation shared by RNS parameter roles.

use primus_distr::{SecretKeySampler, SignedDiscreteGaussian};
use primus_integer::{BigUint, FheUint};
use primus_lattice::RnsGlweSize;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rand::distr::Uniform;

use super::{CrtGlweParametersError, RnsDomainError, validate_moduli};
use crate::SecretKeyDistr;

/// Layout and sampling state shared by ordinary and gadget parameters.
///
/// Base-dependent caches follow the immutable ordered base owned by each outer
/// type: the ordinary codec or the gadget base. No second RNSBase is stored here.
/// Arc sharing retains the same prepared Gaussian tables and secret sampler when
/// gadget parameters are derived, instead of cloning those precomputations.
pub struct CrtGlweEncryptionParameters<T: FheUint> {
    pub(super) size: RnsGlweSize,
    pub(super) cipher_modulus_minus_one: BigUint<Vec<T>>,
    pub(super) cipher_moduli_minus_one: Vec<T>,
    pub(super) cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    pub(super) secret_key_sampler: SecretKeySampler<T>,
    pub(super) noise_distribution: SignedDiscreteGaussian<T::SignedInteger>,
}

impl<T: FheUint> CrtGlweEncryptionParameters<T> {
    /// Prepares a [`CrtGlweEncryptionParameters`] without BFV encoding.
    ///
    /// # Panics
    /// Panics on the layout/base or sampler errors of [`Self::try_new`].
    #[must_use]
    pub fn new<M: FieldContext<T>>(
        size: RnsGlweSize,
        base_q: &RNSBase<T, M>,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(size, base_q, secret_key_distr, noise_standard_deviation)
            .expect("invalid CRT GLWE sampling parameters")
    }

    /// Prepares the complete kN secret and noise domains, without t or gamma.
    /// The base remains owned by the caller; cached samplers follow its exact order.
    /// Mask/noise samplers serve both ordinary and gadget encryption. Different
    /// noise roles must prepare separate states.
    ///
    /// # Errors
    /// Rejects a layout/base modulus-count mismatch, invalid sampler configuration,
    /// fixed secret weights exceeding kN, or support that does not fit every modulus.
    pub fn try_new<M: FieldContext<T>>(
        size: RnsGlweSize,
        base_q: &RNSBase<T, M>,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        if size.moduli_count() != base_q.moduli_count() {
            return Err(RnsDomainError::ModuliCountMismatch {
                expected: size.moduli_count(),
                actual: base_q.moduli_count(),
            }
            .into());
        }
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(size.glwe_size().mask_len())?;
        let noise_distribution = SignedDiscreteGaussian::new(noise_standard_deviation)?;
        let maximum_magnitude = noise_distribution.maximum_magnitude();
        for modulus in base_q.moduli() {
            let modulus_minus_one = modulus.minus_one();
            secret_key_sampler.validate_modulus(modulus_minus_one)?;
            if u128::from(maximum_magnitude) > modulus_minus_one.as_into() {
                return Err(primus_distr::GaussianError::ModulusTooSmall {
                    maximum_magnitude,
                    modulus_minus_one: modulus_minus_one.as_into(),
                }
                .into());
            }
        }

        let mut cipher_modulus_minus_one = BigUint(base_q.moduli_product().0.to_vec());
        let borrow = cipher_modulus_minus_one.sub_value_assign(T::ONE);
        debug_assert!(!borrow);
        Ok(Self {
            size,
            cipher_modulus_minus_one,
            cipher_moduli_minus_one: base_q.moduli().iter().map(|q| q.minus_one()).collect(),
            cipher_moduli_uniform_distr: base_q
                .moduli()
                .iter()
                .map(|q| q.uniform_distribution())
                .collect(),
            secret_key_sampler,
            noise_distribution,
        })
    }

    /// Returns the checked RNS layout; fixed secret weights apply to its kN mask.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }

    /// Returns q_i - 1 in the prepared sampler order.
    #[must_use]
    #[inline]
    pub fn cipher_moduli_minus_one(&self) -> &[T] {
        &self.cipher_moduli_minus_one
    }

    /// Returns the prepared uniform mask samplers in the same modulus order.
    #[must_use]
    #[inline]
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.cipher_moduli_uniform_distr
    }

    /// Returns the secret coefficient proposal distribution.
    #[must_use]
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_sampler.distr()
    }

    /// Returns the sampler for the complete signed coefficient key.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.secret_key_sampler
    }

    /// Returns coefficient-unit noise shared across all RNS limbs.
    #[must_use]
    #[inline]
    pub fn noise_distribution(&self) -> &SignedDiscreteGaussian<T::SignedInteger> {
        &self.noise_distribution
    }

    /// Rechecks only the base-to-cache pairing when assembling independently
    /// prepared parts. Product equality alone cannot establish sampler order.
    pub(crate) fn validate_base<M: FieldContext<T>>(
        &self,
        base_q: &RNSBase<T, M>,
    ) -> Result<(), RnsDomainError<T>> {
        validate_moduli(
            self.cipher_moduli_minus_one
                .iter()
                .map(|&q_minus_one| q_minus_one + T::ONE),
            base_q.moduli().iter().map(|q| q.value()),
        )
    }
}

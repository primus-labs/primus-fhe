//! Immutable layout and sampling precomputation shared by RNS parameter roles.

use primus_distr::{ErrorDistribution, ErrorSampler, SecretKeySampler};
use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rand::distr::Uniform;

use super::{CrtGlweEncryptionParametersError, RnsDomainError, validate_moduli};
use crate::SecretKeyDistr;

/// Layout and sampling precomputation for raw and gadget encryption.
///
/// The ordered RNS basis remains owned by the caller. Evaluators do not depend
/// on this sampling state; gadget encryption receives it separately from the
/// decomposition parameters.
pub struct CrtGlweEncryptionParameters<T: FheUint> {
    pub(super) size: RnsGlweSize,
    pub(super) cipher_moduli_minus_one: Vec<T>,
    pub(super) cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    pub(super) secret_key_sampler: SecretKeySampler<T>,
    pub(super) noise_distribution: ErrorSampler<T>,
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
    ) -> Result<Self, CrtGlweEncryptionParametersError<T>> {
        Self::try_with_error_distribution(
            size,
            base_q,
            secret_key_distr,
            ErrorDistribution::Gaussian {
                standard_deviation: noise_standard_deviation,
            },
        )
    }

    /// Prepares the complete key and an explicit integer error distribution.
    ///
    /// Error coefficients are sampled once across the RNS basis, before any
    /// scheme-specific scaling. CBD is its exact binomial law, not a Gaussian
    /// chosen to have a similar standard deviation. The same ordered-base,
    /// fixed-weight and magnitude conditions as [`Self::try_new`] apply.
    ///
    /// # Errors
    /// Rejects an incompatible layout/base, invalid secret/error distribution,
    /// fixed weights exceeding kN, or support that does not fit every modulus.
    pub fn try_with_error_distribution<M: FieldContext<T>>(
        size: RnsGlweSize,
        base_q: &RNSBase<T, M>,
        secret_key_distr: SecretKeyDistr,
        error_distribution: ErrorDistribution,
    ) -> Result<Self, CrtGlweEncryptionParametersError<T>> {
        if size.moduli_count() != base_q.moduli_count() {
            return Err(RnsDomainError::ModuliCountMismatch {
                expected: size.moduli_count(),
                actual: base_q.moduli_count(),
            }
            .into());
        }
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(size.glwe_size().mask_len())?;
        let noise_distribution = ErrorSampler::try_new(error_distribution)?;
        for modulus in base_q.moduli() {
            let modulus_minus_one = modulus.minus_one();
            secret_key_sampler.validate_modulus(modulus_minus_one)?;
            noise_distribution.validate_modulus(modulus_minus_one)?;
        }

        Ok(Self {
            size,
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
    pub fn noise_distribution(&self) -> &ErrorSampler<T> {
        &self.noise_distribution
    }

    /// Samples coefficient noise into an exact modulus-major RNS polynomial.
    ///
    /// The coefficient count is this core's N. `moduli` may be its Q basis or
    /// an auxiliary expanded basis such as QP; every limb receives the same
    /// logical signed sample. This method checks output shape and support, not
    /// the ordered basis checked by an encryptor/evaluator constructor.
    ///
    /// # Panics
    /// Inherits [`ErrorSampler::sample_crt_to`]'s layout and modulus checks.
    /// Validation precedes writes and random sampling; an RNG panic can leave
    /// partially written output.
    pub fn sample_noise_to<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        output: &mut [T],
        moduli: &[T],
        rng: &mut R,
    ) {
        self.noise_distribution
            .sample_crt_to(output, self.size.poly_length().get(), moduli, rng);
    }

    /// Rechecks the ordered base-to-sampler pairing when composing prepared parts.
    /// Product equality alone cannot establish sampler order. This does not
    /// establish any plaintext recovery condition or transform identity.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] if the modulus count or order differs.
    pub fn validate_base<M: FieldContext<T>>(
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

    /// Checks a prepared transform table against this owner's N and ordered Q.
    ///
    /// Reuses the existing sampling metadata without rebuilding a basis. Actual
    /// root/evaluation order and key identity remain caller contracts.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a polynomial-length or ordered-moduli mismatch.
    pub fn validate_table<Table: NttTable<ValueT = T>>(
        &self,
        table: &DcrtTable<Table>,
    ) -> Result<(), RnsDomainError<T>> {
        let expected = self.size.poly_length().get();
        let actual = table.poly_length().get();
        if expected != actual {
            return Err(RnsDomainError::PolynomialLengthMismatch { expected, actual });
        }
        validate_moduli(
            self.cipher_moduli_minus_one.iter().map(|&q| q + T::ONE),
            table.iter().map(NttTable::modulus),
        )
    }
}

use primus_distr::ErrorDistribution;
use primus_glwe_rns::{SecretKeyDistr, rlwe_parameters::search_ntt_primes};
use primus_modulus::{BarrettModulus, is_prime_u64};
use primus_shape::PolyLength;

use crate::leveled_parameters::{BfvLeveledParameterError, unsupported};
use crate::{BfvContext, BfvParameters};

use super::DEFAULT_DECODER_MODULUS;

/// Numerical context request for the ordinary working-basis multiplication family.
///
/// The returned context is a candidate, not an admitted depth or a security
/// certificate. Pass it to [`crate::planning::BfvLeveledParameters::try_new`] for full admission.
/// The message bound covers every canonical coefficient in the plaintext ring;
/// a slot-value bound alone is not a coefficient bound.
#[derive(Clone, Copy, Debug)]
pub struct BfvLeveledRequest {
    /// Full power-of-two polynomial length.
    pub poly_length: PolyLength,
    /// Plaintext coefficient modulus, strictly between one and the default gamma.
    pub plaintext_modulus: u64,
    /// Also require a prime plaintext modulus supporting all N batching slots.
    pub require_batching: bool,
    /// Bit width of every generated data-Q prime, in 2..=62.
    /// The codec, plaintext and chosen radix can impose stricter conditions.
    pub ciphertext_prime_bits: u32,
    /// Number of generated Q primes and prepared prefix levels, at least two.
    pub ciphertext_prime_count: usize,
    /// Honest ordinary secret-key sampling law; the public ephemeral remains CBD1.
    pub secret_distribution: SecretKeyDistr,
    /// Actual error sampling law, including a Gaussian sampler's hard cutoff.
    pub error_distribution: ErrorDistribution,
}

impl BfvLeveledRequest {
    /// Generates distinct, certified NTT primes and prepares one numerical context.
    ///
    /// # Errors
    /// Rejects unsupported plaintext conditions, finite-search exhaustion or
    /// ordinary parameter/context errors. It does not attempt depth admission.
    pub fn create_context(self) -> Result<BfvContext, BfvLeveledParameterError> {
        let n = self.poly_length.get();
        if self.plaintext_modulus <= 1 || self.plaintext_modulus >= DEFAULT_DECODER_MODULUS {
            return Err(unsupported("plaintext modulus must satisfy 1 < t < gamma"));
        }
        if self.ciphertext_prime_count < 2 {
            return Err(unsupported(
                "working-basis admission needs at least two data primes",
            ));
        }
        if self.require_batching
            && (!is_prime_u64(self.plaintext_modulus)
                || n.checked_mul(2)
                    .is_none_or(|step| !(self.plaintext_modulus - 1).is_multiple_of(step as u64)))
        {
            return Err(unsupported(
                "full batching requires prime t congruent to 1 modulo 2N",
            ));
        }
        let q = search_ntt_primes(
            n,
            self.ciphertext_prime_bits,
            self.ciphertext_prime_count,
            None,
            &[self.plaintext_modulus, DEFAULT_DECODER_MODULUS],
        )?;
        let moduli = q.into_iter().map(BarrettModulus::new).collect::<Vec<_>>();
        let parameters = BfvParameters::try_with_owned_moduli(
            self.poly_length,
            BarrettModulus::new(self.plaintext_modulus),
            BarrettModulus::new(DEFAULT_DECODER_MODULUS),
            moduli,
            self.secret_distribution,
            self.error_distribution,
        )?;
        Ok(BfvContext::try_with_levels(
            parameters,
            self.ciphertext_prime_count,
        )?)
    }
}

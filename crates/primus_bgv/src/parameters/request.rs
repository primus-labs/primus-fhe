use primus_distr::ErrorDistribution;
use primus_glwe_rns::{SecretKeyDistr, rlwe_parameters::search_ntt_primes};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::planning::BgvPlanningError;
use crate::{BgvContext, BgvParameters, BgvParametersError};

/// A bounded ordinary parameter-generation request, separate from circuit admission.
///
/// N, prime width/count and levels are explicit resource choices. Generation
/// finds actual primes, not an optimal Q or a security level. Adjust these
/// choices using a rejected circuit node's required-bit diagnostic.
pub struct BgvParameterRequest {
    /// Full coefficient polynomial length N, a supported power of two.
    pub poly_length: PolyLength,
    /// Coefficient plaintext modulus p; coefficient arithmetic permits composite p.
    pub plaintext_modulus: u64,
    /// Bit width of each generated ciphertext prime, below the native 62-bit limit.
    pub ciphertext_prime_bits: u32,
    /// Number of ordered top-level ciphertext primes.
    pub ciphertext_prime_count: usize,
    /// Number of prefix levels to prepare, including level zero.
    pub level_count: usize,
    /// Actual client secret distribution, also used for the target of ordinary switching.
    pub secret_distribution: SecretKeyDistr,
    /// Actual bounded error sampler, shared by ordinary encryption/key generation.
    pub error_distribution: ErrorDistribution,
}

impl BgvParameterRequest {
    /// Generates ordinary NTT primes, validates them and prepares one context.
    /// The ciphertext primes need not be one modulo the plaintext modulus.
    ///
    /// This establishes arithmetic compatibility and the constructor's fresh
    /// private recovery bound. Call [`crate::planning::BgvCircuitPlan::try_new`] for the complete
    /// declared public/evaluated circuit. Neither operation establishes RLWE security.
    pub fn create_context(&self) -> Result<BgvContext, BgvPlanningError> {
        let plaintext_modulus = BarrettModulus::try_new(self.plaintext_modulus)
            .ok_or(BgvParametersError::PlainModulus)?;
        let primes = search_ntt_primes(
            self.poly_length.get(),
            self.ciphertext_prime_bits,
            self.ciphertext_prime_count,
            None,
            &[],
        )?;
        let moduli = primes
            .into_iter()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>();
        let parameters = BgvParameters::try_with_owned_moduli(
            self.poly_length,
            plaintext_modulus,
            moduli,
            self.secret_distribution,
            self.error_distribution,
        )?;
        Ok(BgvContext::try_with_levels(parameters, self.level_count)?)
    }
}

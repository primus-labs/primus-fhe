use num_traits::ConstZero;
use primus_integer::{FheUint, SignedInteger};
use rand::distr::Distribution;

use crate::{CenteredBinomial, CenteredBinomialError, GaussianError, SignedDiscreteGaussian};

/// Distribution of independent integer error coefficients, before scheme scaling.
/// Secret-key and ephemeral-key roles choose their distributions separately.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorDistribution {
    /// Truncated discrete Gaussian, using the existing facade and default tail cut.
    Gaussian {
        /// Gaussian scale parameter in coefficient units.
        standard_deviation: f64,
    },
    /// Exact difference of independent eta-bit Hamming weights.
    CenteredBinomial {
        /// Binomial parameter in 1..=32; CBD1 and CBD21 use 1 and 21.
        eta: u32,
    },
}

/// Invalid error distribution or insufficient modular output range.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ErrorSamplerError {
    /// Gaussian preparation failed.
    #[error("invalid Gaussian error distribution")]
    Gaussian(#[from] GaussianError),
    /// Centered-binomial preparation failed.
    #[error(transparent)]
    CenteredBinomial(#[from] CenteredBinomialError),
    /// A modulus must encode the complete inclusive signed support.
    #[error(
        "error maximum magnitude {maximum_magnitude} must not exceed modulus minus one {modulus_minus_one}"
    )]
    ModulusTooSmall {
        /// Inclusive bound on every error sample's magnitude.
        maximum_magnitude: u64,
        /// Supplied modulus minus one; T::MAX can denote a native modulus.
        modulus_minus_one: u128,
    },
}

/// Prepared error sampling with signed and canonical RNS representations.
///
/// T is the unsigned coefficient type. Immutable Gaussian tables are prepared
/// once; batches select a concrete backend before their coefficient loop.
#[derive(Clone)]
pub struct ErrorSampler<T: FheUint> {
    distribution: ErrorDistribution,
    method: SamplingMethod<T>,
}

#[derive(Clone)]
enum SamplingMethod<T: FheUint> {
    Gaussian(SignedDiscreteGaussian<T::SignedInteger>),
    CenteredBinomial(CenteredBinomial<T::SignedInteger>),
}

impl<T: FheUint> ErrorSampler<T> {
    /// Prepares a sampler without retaining any modulus or RNG state.
    ///
    /// # Errors
    /// Returns the selected distribution's construction error, including an
    /// invalid scale/eta or a support too wide for T's signed companion.
    pub fn try_new(distribution: ErrorDistribution) -> Result<Self, ErrorSamplerError> {
        let method = match distribution {
            ErrorDistribution::Gaussian { standard_deviation } => {
                SamplingMethod::Gaussian(SignedDiscreteGaussian::new(standard_deviation)?)
            }
            ErrorDistribution::CenteredBinomial { eta } => {
                SamplingMethod::CenteredBinomial(CenteredBinomial::new(eta)?)
            }
        };
        Ok(Self {
            distribution,
            method,
        })
    }

    /// Returns the mathematical distribution configuration.
    #[must_use]
    pub fn distribution(&self) -> ErrorDistribution {
        self.distribution
    }

    /// Returns the inclusive bound on every sampled coefficient magnitude.
    #[must_use]
    pub fn maximum_magnitude(&self) -> u64 {
        match &self.method {
            SamplingMethod::Gaussian(gaussian) => gaussian.maximum_magnitude(),
            SamplingMethod::CenteredBinomial(binomial) => u64::from(binomial.eta()),
        }
    }

    /// Returns the Gaussian scale or the exact CBD standard deviation sqrt(eta/2).
    /// Equal values do not make these distributions interchangeable.
    #[must_use]
    pub fn standard_deviation(&self) -> f64 {
        match self.distribution {
            ErrorDistribution::Gaussian { standard_deviation } => standard_deviation,
            ErrorDistribution::CenteredBinomial { eta } => (f64::from(eta) / 2.0).sqrt(),
        }
    }

    /// Checks that an output modulus can encode the full signed support.
    /// T::MAX denotes the modulus-minus-one of native arithmetic.
    ///
    /// # Errors
    /// Returns ModulusTooSmall when the inclusive bound exceeds modulus_minus_one.
    pub fn validate_modulus(&self, modulus_minus_one: T) -> Result<(), ErrorSamplerError> {
        let maximum_magnitude = self.maximum_magnitude();
        let modulus_minus_one = modulus_minus_one.as_into();
        if u128::from(maximum_magnitude) > modulus_minus_one {
            Err(ErrorSamplerError::ModulusTooSmall {
                maximum_magnitude,
                modulus_minus_one,
            })
        } else {
            Ok(())
        }
    }

    /// Overwrites signed coefficients without allocation. Empty output consumes
    /// no randomness; a panicking RNG may leave partial output.
    pub fn sample_signed_to<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        output: &mut [T::SignedInteger],
        rng: &mut R,
    ) {
        match &self.method {
            SamplingMethod::Gaussian(gaussian) => gaussian.sample_to(output, rng),
            SamplingMethod::CenteredBinomial(binomial) => binomial.sample_to(output, rng),
        }
    }

    /// Overwrites a complete modulus-major CRT batch without allocation.
    ///
    /// Samples each integer coefficient once, then encodes that same signed
    /// sample under every modulus in order. Output has exactly
    /// coefficient_count*moduli.len() values. Empty batches consume no randomness.
    /// A panicking RNG can leave partial output; other validation precedes writes.
    ///
    /// # Panics
    /// Panics on a length overflow/mismatch, zero modulus, or a modulus that
    /// cannot encode the complete signed support.
    pub fn sample_crt_to<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        output: &mut [T],
        coefficient_count: usize,
        moduli: &[T],
        rng: &mut R,
    ) {
        let expected = coefficient_count
            .checked_mul(moduli.len())
            .expect("CRT error output length overflow");
        assert_eq!(output.len(), expected, "CRT error output length mismatch");
        for &modulus in moduli {
            assert!(modulus > T::ZERO, "CRT error modulus must be nonzero");
            self.validate_modulus(modulus - T::ONE)
                .expect("CRT error modulus cannot encode the sample support");
        }
        if output.is_empty() {
            return;
        }
        match &self.method {
            SamplingMethod::Gaussian(SignedDiscreteGaussian::Cdt(sampler)) => {
                sample_crt_kernel(output, coefficient_count, moduli, sampler, rng);
            }
            SamplingMethod::Gaussian(SignedDiscreteGaussian::Ziggurat(sampler)) => {
                sample_crt_kernel(output, coefficient_count, moduli, sampler, rng);
            }
            SamplingMethod::CenteredBinomial(sampler) => {
                sample_crt_kernel(output, coefficient_count, moduli, sampler, rng);
            }
        }
    }
}

impl<T: FheUint> Distribution<T::SignedInteger> for ErrorSampler<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T::SignedInteger {
        match &self.method {
            SamplingMethod::Gaussian(sampler) => sampler.sample(rng),
            SamplingMethod::CenteredBinomial(sampler) => sampler.sample(rng),
        }
    }
}

/// Complete layouts and support bounds have been established by the owner.
pub(crate) fn sample_crt_kernel<T, D, R>(
    output: &mut [T],
    coefficient_count: usize,
    moduli: &[T],
    sampler: &D,
    rng: &mut R,
) where
    T: FheUint,
    D: Distribution<T::SignedInteger>,
    R: rand::Rng + ?Sized,
{
    for coefficient in 0..coefficient_count {
        let sample = sampler.sample(rng);
        if sample >= T::SignedInteger::ZERO {
            let residue = sample.cast_to_unsigned();
            for value in output
                .iter_mut()
                .skip(coefficient)
                .step_by(coefficient_count)
            {
                *value = residue;
            }
        } else {
            for (value, &modulus) in output
                .iter_mut()
                .skip(coefficient)
                .step_by(coefficient_count)
                .zip(moduli)
            {
                *value = T::wrapping_add_signed(modulus, sample);
            }
        }
    }
}

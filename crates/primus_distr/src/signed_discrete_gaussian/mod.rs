use primus_integer::{FheInt, FheUint, SignedInteger};
use rand::distr::Distribution;

use crate::{
    GaussianError,
    gaussian_core::{CDT_MAX_MAGNITUDE, DEFAULT_TAIL_CUT, GaussianParameters},
};

mod cdt;
#[cfg(feature = "high_precision")]
mod precise_cdt;
mod ziggurat;

pub use cdt::SignedCDTSampler;
#[cfg(feature = "high_precision")]
pub use precise_cdt::SignedPreciseCDTSampler;
pub use ziggurat::SignedDiscreteZiggurat;

/// A centered discrete Gaussian distribution over signed integers.
///
/// Samples can be positive, zero, or negative. Internally delegates to
/// [`SignedCDTSampler`] when the truncated support fits its table, and to
/// [`SignedDiscreteZiggurat`] otherwise.
#[derive(Clone)]
pub enum SignedDiscreteGaussian<T: FheInt + SignedInteger> {
    /// CDT (cumulative distribution table) based sampler.
    Cdt(SignedCDTSampler<T>),
    /// Ziggurat based sampler.
    Ziggurat(SignedDiscreteZiggurat<T>),
}

impl<T: FheInt + SignedInteger> SignedDiscreteGaussian<T> {
    /// Construct a signed discrete Gaussian sampler.
    ///
    /// Automatically selects the CDT or Ziggurat backend based on `std_dev`.
    ///
    /// # Parameters
    /// - `std_dev` — standard deviation (`σ`), which must be finite and at
    ///   least [`MIN_STANDARD_DEVIATION`](crate::MIN_STANDARD_DEVIATION).
    ///
    /// # Errors
    ///
    /// Returns an error when `std_dev` is invalid or the truncated support
    /// cannot be represented by `T`.
    #[inline]
    pub fn new(std_dev: f64) -> Result<SignedDiscreteGaussian<T>, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, DEFAULT_TAIL_CUT)?;
        if parameters.maximum_magnitude() <= CDT_MAX_MAGNITUDE {
            SignedCDTSampler::from_parameters(parameters).map(SignedDiscreteGaussian::Cdt)
        } else {
            SignedDiscreteZiggurat::from_parameters(parameters)
                .map(SignedDiscreteGaussian::Ziggurat)
        }
    }

    /// Returns the standard deviation of this [`SignedDiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
        }
    }

    /// Returns the inclusive maximum coefficient magnitude in the truncated
    /// support, including when constructed from a backend with a custom tail cut.
    #[must_use]
    #[inline]
    pub fn maximum_magnitude(&self) -> u64 {
        match self {
            Self::Cdt(sampler) => sampler.maximum_magnitude(),
            Self::Ziggurat(sampler) => sampler.maximum_magnitude(),
        }
    }

    /// Samples `length` signed coefficients into a newly allocated vector.
    /// Selects the backend once and initializes the vector directly from samples.
    /// Produces the same samples and consumes the same randomness as repeated
    /// scalar [`Distribution::sample`] calls; an empty vector consumes none.
    #[must_use]
    #[inline]
    pub fn sample_vec<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        length: usize,
        rng: &mut R,
    ) -> Vec<T> {
        match self {
            Self::Cdt(sampler) => (0..length).map(|_| sampler.sample(rng)).collect(),
            Self::Ziggurat(sampler) => (0..length).map(|_| sampler.sample(rng)).collect(),
        }
    }

    /// Overwrites `output` with signed coefficients without allocating.
    /// Selects the backend once, before the coefficient loop. Samples and RNG
    /// consumption match repeated scalar [`Distribution::sample`] calls;
    /// an empty slice consumes no randomness. A panicking RNG may leave
    /// partially written output.
    #[inline]
    pub fn sample_to<R: rand::Rng + rand::CryptoRng + ?Sized>(
        &self,
        output: &mut [T],
        rng: &mut R,
    ) {
        match self {
            Self::Cdt(sampler) => crate::gaussian_core::sample_to(output, sampler, rng),
            Self::Ziggurat(sampler) => crate::gaussian_core::sample_to(output, sampler, rng),
        }
    }

    /// Initializes encoded storage directly after the owner validates the modulus.
    pub(crate) fn sample_encoded<U: FheUint, R: rand::Rng + rand::CryptoRng>(
        &self,
        length: usize,
        modulus_minus_one: U,
        rng: &mut R,
    ) -> Vec<U>
    where
        T: SignedInteger<UnsignedInteger = U>,
    {
        match self {
            Self::Cdt(sampler) => (0..length)
                .map(|_| sampler.sample_encoded(modulus_minus_one, rng))
                .collect(),
            Self::Ziggurat(sampler) => (0..length)
                .map(|_| sampler.sample_encoded(modulus_minus_one, rng))
                .collect(),
        }
    }

    /// Selects the encoded batch kernel once using the shared Gaussian tables.
    pub(crate) fn sample_encoded_to<U: FheUint, R: rand::Rng + rand::CryptoRng>(
        &self,
        output: &mut [U],
        modulus_minus_one: U,
        rng: &mut R,
    ) where
        T: SignedInteger<UnsignedInteger = U>,
    {
        match self {
            Self::Cdt(sampler) => {
                for value in output {
                    *value = sampler.sample_encoded(modulus_minus_one, rng);
                }
            }
            Self::Ziggurat(sampler) => {
                for value in output {
                    *value = sampler.sample_encoded(modulus_minus_one, rng);
                }
            }
        }
    }
}

impl<T: FheInt + SignedInteger> Distribution<T> for SignedDiscreteGaussian<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.sample(rng),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.sample(rng),
        }
    }
}

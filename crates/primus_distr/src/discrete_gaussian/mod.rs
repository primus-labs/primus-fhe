use primus_integer::FheUint;
use rand::{Rng, distr::Distribution};

mod cdt;
#[cfg(feature = "high_precision")]
mod precise_cdt;
mod ziggurat;

pub use cdt::CDTSampler;
#[cfg(feature = "high_precision")]
pub use precise_cdt::PreciseCDTSampler;
pub use ziggurat::DiscreteZiggurat;

use crate::{
    GaussianError,
    gaussian_core::{CDT_MAX_MAGNITUDE, DEFAULT_TAIL_CUT, GaussianParameters},
};

/// A centered discrete Gaussian distribution over unsigned integers.
///
/// Samples are non-negative. Negative values from the underlying distribution
/// are mapped into the upper half of the modulus range via
/// `modulus_minus_one - |x| + 1`.
///
/// Internally delegates to [`CDTSampler`] when the truncated support fits its
/// table, and to [`DiscreteZiggurat`] otherwise.
#[derive(Clone)]
pub enum DiscreteGaussian<T: FheUint> {
    /// CDT (cumulative distribution table) based sampler.
    Cdt(CDTSampler<T>),
    /// Ziggurat based sampler.
    Ziggurat(DiscreteZiggurat<T>),
}

impl<T: FheUint> DiscreteGaussian<T> {
    /// Construct a discrete Gaussian sampler.
    ///
    /// Automatically selects the CDT or Ziggurat backend based on `std_dev`.
    ///
    /// # Parameters
    /// - `std_dev` — standard deviation (`σ`), must be at least
    ///   [`MIN_STANDARD_DEVIATION`](crate::MIN_STANDARD_DEVIATION).
    /// - `modulus_minus_one` — the modulus minus one, used to wrap negative
    ///   samples into the unsigned range.
    ///
    /// # Errors
    ///
    /// Returns an error when `std_dev` is smaller than
    /// [`MIN_STANDARD_DEVIATION`](crate::MIN_STANDARD_DEVIATION) or cannot be
    /// used by the floating-point kernels, or when the truncated support does
    /// not fit below the supplied modulus.
    #[inline]
    pub fn new(std_dev: f64, modulus_minus_one: T) -> Result<DiscreteGaussian<T>, GaussianError> {
        let parameters = GaussianParameters::new(std_dev, DEFAULT_TAIL_CUT)?;
        if parameters.maximum_magnitude() <= CDT_MAX_MAGNITUDE {
            CDTSampler::from_parameters(parameters, modulus_minus_one).map(DiscreteGaussian::Cdt)
        } else {
            DiscreteZiggurat::from_parameters(parameters, modulus_minus_one)
                .map(DiscreteGaussian::Ziggurat)
        }
    }

    /// Returns the standard deviation of this [`DiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            DiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            DiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
        }
    }

    /// Returns the modulus minus one used to encode negative samples.
    #[must_use]
    #[inline]
    pub fn modulus_minus_one(&self) -> T {
        match self {
            Self::Cdt(sampler) => sampler.modulus_minus_one(),
            Self::Ziggurat(sampler) => sampler.modulus_minus_one(),
        }
    }

    /// Samples `length` canonical residues into a newly allocated vector.
    /// Selects the backend once and initializes the vector directly from samples.
    /// Produces the same samples and consumes the same randomness as repeated
    /// scalar [`Distribution::sample`] calls; an empty vector consumes none.
    #[must_use]
    #[inline]
    pub fn sample_vec<R: Rng + rand::CryptoRng + ?Sized>(
        &self,
        length: usize,
        rng: &mut R,
    ) -> Vec<T> {
        match self {
            Self::Cdt(sampler) => (0..length).map(|_| sampler.sample(rng)).collect(),
            Self::Ziggurat(sampler) => (0..length).map(|_| sampler.sample(rng)).collect(),
        }
    }

    /// Overwrites `output` with canonical residues without allocating.
    /// Selects the backend once, before the coefficient loop. Samples and RNG
    /// consumption match repeated scalar [`Distribution::sample`] calls;
    /// an empty slice consumes no randomness. A panicking RNG may leave
    /// partially written output.
    #[inline]
    pub fn sample_to<R: Rng + rand::CryptoRng + ?Sized>(&self, output: &mut [T], rng: &mut R) {
        match self {
            Self::Cdt(sampler) => crate::gaussian_core::sample_to(output, sampler, rng),
            Self::Ziggurat(sampler) => crate::gaussian_core::sample_to(output, sampler, rng),
        }
    }
}

impl<T: FheUint> Distribution<T> for DiscreteGaussian<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            DiscreteGaussian::Cdt(sampler) => sampler.sample(rng),
            DiscreteGaussian::Ziggurat(sampler) => sampler.sample(rng),
        }
    }
}

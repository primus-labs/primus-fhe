use primus_integer::FheUint;
use rand::{Rng, distr::Distribution};

mod cdt;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
mod unix_cdt;
mod ziggurat;

pub use cdt::CDTSampler;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
pub use unix_cdt::UnixCDTSampler;
pub use ziggurat::DiscreteZiggurat;

use crate::DistrErr;

/// A centered discrete Gaussian distribution over unsigned integers.
///
/// Samples are non-negative. Negative values from the underlying distribution
/// are mapped into the upper half of the modulus range via
/// `modulus_minus_one - |x| + 1`.
///
/// Internally delegates to [`CDTSampler`] (σ ≤ 20) or
/// [`DiscreteZiggurat`] (σ > 20).
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
    /// - `std_dev` — standard deviation (`σ`), must be at least 0.7.
    /// - `modulus_minus_one` — the modulus minus one, used to wrap negative
    ///   samples into the unsigned range.
    #[inline]
    pub fn new(std_dev: f64, modulus_minus_one: T) -> Result<DiscreteGaussian<T>, DistrErr<T>> {
        if std_dev < 0.7 {
            Err(DistrErr::InvalidStdDev {
                std_dev,
                modulus_minus_one,
            })
        } else if std_dev <= 20.0 {
            Ok(DiscreteGaussian::Cdt(CDTSampler::new(
                std_dev,
                12.0,
                modulus_minus_one,
            )))
        } else {
            Ok(DiscreteGaussian::Ziggurat(DiscreteZiggurat::new(
                std_dev,
                12.0,
                modulus_minus_one,
            )))
        }
    }

    /// Construct with an explicit upper bound on the standard deviation.
    ///
    /// Returns an error if `std_dev` is outside the range
    /// `[0.7, max_std_dev)`.
    ///
    /// # Panics
    /// Currently panics (via `unimplemented!()`) when the parameters are
    /// valid — this constructor is reserved for future use.
    #[inline]
    pub fn new_with_max_limit(
        std_dev: f64,
        max_std_dev: f64,
        modulus_minus_one: T,
    ) -> Result<DiscreteGaussian<T>, DistrErr<T>> {
        if max_std_dev <= std_dev || std_dev < 0.7 {
            return Err(DistrErr::InvalidStdDev {
                std_dev,
                modulus_minus_one,
            });
        }
        unimplemented!()
    }

    /// Returns the standard deviation of this [`DiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            DiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            DiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
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

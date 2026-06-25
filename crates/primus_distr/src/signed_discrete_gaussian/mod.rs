use primus_integer::FheInt;
use rand::distr::Distribution;

use crate::DistrErr;

mod cdt;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
mod unix_cdt;
mod ziggurat;

pub use cdt::SignedCDTSampler;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
pub use unix_cdt::SignedUnixCDTSampler;
pub use ziggurat::SignedDiscreteZiggurat;

/// A centered discrete Gaussian distribution over signed integers.
///
/// Samples can be positive, zero, or negative. Internally delegates to
/// [`SignedCDTSampler`] (σ ≤ 20) or [`SignedDiscreteZiggurat`] (σ > 20).
#[derive(Clone)]
pub enum SignedDiscreteGaussian<T: FheInt> {
    /// CDT (cumulative distribution table) based sampler.
    Cdt(SignedCDTSampler<T>),
    /// Ziggurat based sampler.
    Ziggurat(SignedDiscreteZiggurat<T>),
}

impl<T: FheInt> SignedDiscreteGaussian<T> {
    /// Construct a signed discrete Gaussian sampler.
    ///
    /// Automatically selects the CDT or Ziggurat backend based on `std_dev`.
    ///
    /// # Parameters
    /// - `std_dev` — standard deviation (`σ`).
    #[inline]
    pub fn new(std_dev: f64) -> Result<SignedDiscreteGaussian<T>, DistrErr<T>> {
        if std_dev <= 20.0 {
            Ok(SignedDiscreteGaussian::Cdt(SignedCDTSampler::new(
                std_dev, 12.0,
            )))
        } else {
            Ok(SignedDiscreteGaussian::Ziggurat(
                SignedDiscreteZiggurat::new(std_dev, 12.0),
            ))
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
    ) -> Result<SignedDiscreteGaussian<T>, DistrErr<T>> {
        if max_std_dev <= std_dev || std_dev < 0.7 {
            return Err(DistrErr::InvalidStdDev {
                std_dev,
                modulus_minus_one: T::ZERO,
            });
        }
        unimplemented!()
    }

    /// Returns the standard deviation of this [`SignedDiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
        }
    }
}

impl<T: FheInt> Distribution<T> for SignedDiscreteGaussian<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.sample(rng),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.sample(rng),
        }
    }
}

//! This module defines a trait to get some distributions easily.

use rand_distr::{uniform::SampleUniform, Distribution, Normal};

use crate::AlgebraError;

/// Defines a trait for sampling from various mathematical distributions over a field.
///
/// This trait specifies the ability to create different types of distributions that can be sampled,
/// which is particularly useful in the context of probabilistic cryptographic schemes and other
/// algorithms that require randomness with specific statistical properties.
///
/// The trait is bound by `Sized`, ensuring that the trait can only be implemented by types with a known
/// size at compile time, and `SampleUniform`, which allows for uniform sampling over a range.
///
/// Types implementing this trait must define four associated distribution types: standard, binary, ternary and gaussian,
/// each of which must implement the `Distribution` trait. This setup allows for sampling from these
/// distributions in a generic manner.
///
/// # Associated Types
/// * `StandardDistribution`: A distribution that produces all values uniformly.
///
/// # Methods
/// * `standard_distribution()`: Returns an instance of the standard distribution type.
/// * `binary_sampler()`: Returns an instance of the binary sampler type.
/// * `ternary_sampler()`: Returns an instance of the ternary sampler type.
/// * `gaussian_sampler(mean, std_dev)`: Returns an instance of the gaussian sampler type, parameterized by the specified mean and standard deviation.
///   This method may fail, indicated by returning an `AlgebraError`, if the parameters do not result in a valid sampler.
pub trait Random: Sized + SampleUniform {
    /// The thpe of the standard distribution.
    type StandardDistribution: Distribution<Self> + Copy;

    /// Get the standard distribution.
    fn standard_distribution() -> Self::StandardDistribution;

    /// Get the binary sampler.
    fn binary_sampler() -> FieldBinarySampler;

    /// Get the ternary sampler.
    fn ternary_sampler() -> FieldTernarySampler;

    /// Get the gaussian sampler.
    fn gaussian_sampler(
        mean: f64,
        std_dev: f64,
    ) -> Result<FieldDiscreteGaussianSampler, AlgebraError>;

    /// Get the gaussian distribution.
    fn gaussian_sampler_with_max_limit(
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<FieldDiscreteGaussianSampler, AlgebraError>;
}

/// The binary distribution for Field.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldBinarySampler;

/// The ternary distribution for Field.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldTernarySampler;

/// The gaussian distribution `N(mean, std_dev**2)` for Field.
#[derive(Clone, Copy, Debug)]
pub struct FieldDiscreteGaussianSampler {
    gaussian: Normal<f64>,
    max_std_dev: f64,
    cbd_enable: bool,
}

impl FieldDiscreteGaussianSampler {
    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new(mean: f64, std_dev: f64) -> Result<FieldDiscreteGaussianSampler, AlgebraError> {
        let max_std_dev = std_dev * 6.0;
        if std_dev < 0. {
            return Err(AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(gaussian) => Ok(FieldDiscreteGaussianSampler {
                gaussian,
                max_std_dev,
                cbd_enable: mean.to_bits() == 0.0f64.to_bits()
                    && std_dev.to_bits() == 3.2f64.to_bits(),
            }),
            Err(_) => Err(AlgebraError::DistributionError),
        }
    }

    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new_with_max(
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<FieldDiscreteGaussianSampler, AlgebraError> {
        if max_std_dev <= std_dev || std_dev < 0. {
            return Err(AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(gaussian) => Ok(FieldDiscreteGaussianSampler {
                gaussian,
                max_std_dev,
                cbd_enable: mean.to_bits() == 0.0f64.to_bits()
                    && std_dev.to_bits() == 3.2f64.to_bits(),
            }),
            Err(_) => Err(AlgebraError::DistributionError),
        }
    }

    /// Returns the mean (`μ`) of the distribution.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.gaussian.mean()
    }

    /// Returns the standard deviation (`σ`) of the distribution.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.gaussian.std_dev()
    }

    /// Returns max deviation of the distribution.
    #[inline]
    pub fn max_std_dev(&self) -> f64 {
        self.max_std_dev
    }

    /// Returns the inner gaussian of this [`FieldDiscreteGaussianSampler`].
    #[inline]
    pub fn gaussian(&self) -> Normal<f64> {
        self.gaussian
    }

    /// Returns the cbd enable of this [`FieldDiscreteGaussianSampler`].
    #[inline]
    pub fn cbd_enable(&self) -> bool {
        self.cbd_enable
    }
}

//! This module defines a trait to get some distributions easily.

use rand_distr::{Distribution, Normal};

use crate::{AlgebraError, Field};

/// Defines a trait for sampling from various mathematical distributions over a field.
///
/// This trait specifies the ability to create different types of distributions that can be sampled,
/// which is particularly useful in the context of probabilistic cryptographic schemes and other
/// algorithms that require randomness with specific statistical properties.
///
/// The trait is bound by `Sized`, ensuring that the trait can only be implemented by types with a known
/// size at compile time, and `SampleUniform`, which allows for uniform sampling over a range.
///
/// Types implementing this trait must define four associated sampler types: uniform, binary, ternary and gaussian,
/// each of which must implement the `Distribution` trait. This setup allows for sampling from these
/// distributions in a generic manner.
///
/// # Associated Types
/// * `UniformSampler`: A sampler that produces all values uniformly.
///
/// # Methods
/// * `uniform_sampler()`: Returns an instance of the uniform sampler type.
/// * `binary_sampler()`: Returns an instance of the binary sampler type.
/// * `ternary_sampler()`: Returns an instance of the ternary sampler type.
/// * `gaussian_sampler(mean, std_dev)`: Returns an instance of the gaussian sampler type, parameterized by the specified mean and standard deviation.
///   This method may fail, indicated by returning an `AlgebraError`, if the parameters do not result in a valid sampler.
pub trait Random: Field {
    /// A sampler that produces all values uniformly.
    type UniformSampler: Distribution<Self> + Copy;

    /// Get the uniform sampler.
    fn uniform_sampler() -> Self::UniformSampler;

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

/// The uniform sampler for Field.
#[derive(Clone, Copy)]
pub struct FieldUniformSampler<F: Field> {
    /// low
    pub low: F::Value,
    /// range
    pub range: F::Value,
    /// thresh
    pub thresh: F::Value,
}

/// The binary sampler for Field.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldBinarySampler;

/// The ternary sampler for Field.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldTernarySampler;

/// The gaussian sampler `N(mean, std_dev**2)` for Field.
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

    /// Returns the mean (`μ`) of the sampler.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.gaussian.mean()
    }

    /// Returns the standard deviation (`σ`) of the sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.gaussian.std_dev()
    }

    /// Returns max deviation of the sampler.
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

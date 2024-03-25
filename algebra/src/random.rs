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
/// Types implementing this trait must define four associated distribution types: standard, binary, ternary and gaussain,
/// each of which must implement the `Distribution` trait. This setup allows for sampling from these
/// distributions in a generic manner.
///
/// # Associated Types
/// * `StandardDistribution`: A distribution that produces all values uniformly.
///
/// # Methods
/// * `standard_distribution()`: Returns an instance of the standard distribution type.
/// * `binary_distribution()`: Returns an instance of the binary distribution type.
/// * `ternary_distribution()`: Returns an instance of the ternary distribution type.
/// * `gaussain_distribution(mean, std_dev)`: Returns an instance of the gaussain distribution type, parameterized by the specified mean and standard deviation.
///   This method may fail, indicated by returning an `AlgebraError`, if the parameters do not result in a valid distribution.
pub trait Random: Sized + SampleUniform {
    /// The thpe of the standard distribution.
    type StandardDistribution: Distribution<Self> + Copy;

    /// Get the standard distribution.
    fn standard_distribution() -> Self::StandardDistribution;

    /// Get the binary distribution.
    fn binary_distribution() -> FieldBinarySampler;

    /// Get the ternary distribution.
    fn ternary_distribution() -> FieldTernarySampler;

    /// Get the gaussain distribution.
    fn gaussain_distribution(
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<FieldDiscreteGaussainSampler, AlgebraError>;
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

/// The gaussain distribution `N(mean, std_dev**2)` for Field.
#[derive(Clone, Copy, Debug)]
pub struct FieldDiscreteGaussainSampler {
    gaussain: Normal<f64>,
    max_std_dev: f64,
    cbd_enable: bool,
}

impl FieldDiscreteGaussainSampler {
    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new(
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<FieldDiscreteGaussainSampler, AlgebraError> {
        if max_std_dev <= std_dev || std_dev < 0. {
            return Err(AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(gaussain) => Ok(FieldDiscreteGaussainSampler {
                gaussain,
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
        self.gaussain.mean()
    }

    /// Returns the standard deviation (`σ`) of the distribution.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.gaussain.std_dev()
    }

    /// Returns max deviation of the distribution.
    #[inline]
    pub fn max_std_dev(&self) -> f64 {
        self.max_std_dev
    }

    /// Returns the inner gaussain of this [`FieldDiscreteGaussainSampler`].
    #[inline]
    pub fn gaussain(&self) -> Normal<f64> {
        self.gaussain
    }

    /// Returns the cbd enable of this [`FieldDiscreteGaussainSampler`].
    #[inline]
    pub fn cbd_enable(&self) -> bool {
        self.cbd_enable
    }
}

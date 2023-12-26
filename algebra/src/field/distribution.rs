//! This module defines a trait to get some distributions easily.

use rand_distr::{uniform::SampleUniform, Distribution};

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
/// Types implementing this trait must define three associated distribution types: binary, ternary, and normal,
/// each of which must implement the `Distribution` trait. This setup allows for sampling from these
/// distributions in a generic manner.
///
/// # Associated Types
/// * `StandardDistribution`: A distribution that produces all values uniformly.
/// * `BinaryDistribution`: A distribution that produces binary (0 or 1) samples.
/// * `TernaryDistribution`: A distribution that produces ternary (-1, 0, or 1) samples.
/// * `NormalDistribution`: A distribution that produces samples according to a normal (Gaussian) distribution.
///
/// # Methods
/// * `standard_distribution()`: Returns an instance of the standard distribution type.
/// * `binary_distribution()`: Returns an instance of the binary distribution type.
/// * `ternary_distribution()`: Returns an instance of the ternary distribution type.
/// * `normal_distribution(mean, std_dev)`: Returns an instance of the normal distribution type, parameterized by the specified mean and standard deviation.
///   This method may fail, indicated by returning an `AlgebraError`, if the parameters do not result in a valid distribution.
pub trait Random: Sized + SampleUniform {
    /// The thpe of the standard distribution.
    type StandardDistribution: Distribution<Self> + Copy;

    /// The type of the binary distribution.
    type BinaryDistribution: Distribution<Self> + Copy;

    /// The type of the ternary distribution.
    type TernaryDistribution: Distribution<Self> + Copy;

    /// The type of the normal distribution.
    type NormalDistribution: Distribution<Self> + Copy;

    /// Get the standard distribution.
    fn standard_distribution() -> Self::StandardDistribution;

    /// Get the binary distribution.
    fn binary_distribution() -> Self::BinaryDistribution;

    /// Get the ternary distribution.
    fn ternary_distribution() -> Self::TernaryDistribution;

    /// Get the normal distribution.
    fn normal_distribution(
        mean: f64,
        std_dev: f64,
    ) -> Result<Self::NormalDistribution, AlgebraError>;
}

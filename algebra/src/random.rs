//! This module defines a trait to get some distributions easily.

use rand::Rng;
use rand_distr::{Distribution, Normal};

use crate::{AlgebraError, AsFrom, AsInto, Field, Widening, WrappingOps};

/// The uniform sampler for Field.
#[derive(Clone, Copy)]
pub struct FieldUniformSampler<F: Field> {
    /// low
    low: F::Value,
    /// range
    range: F::Value,
    /// thresh
    thresh: F::Value,
}

impl<F: Field> FieldUniformSampler<F> {
    /// Creates a new [`FieldUniformSampler<F>`].
    #[inline]
    pub fn new() -> Self {
        Self {
            low: F::ZERO.get(),
            range: F::MODULUS_VALUE,
            thresh: {
                let range = F::SampleType::as_from(F::MODULUS_VALUE);
                (range.wrapping_neg() % range).as_into()
            },
        }
    }
}

impl<F: Field> Default for FieldUniformSampler<F> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> Distribution<F> for FieldUniformSampler<F> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        let range = F::SampleType::as_from(self.range);
        let thresh = F::SampleType::as_from(self.thresh);
        let hi = loop {
            let (lo, hi) = F::gen_sample(rng).widen_mul(range);
            if lo >= thresh {
                break hi;
            }
        };
        F::new(self.low.wrapping_add(hi.as_into()))
    }
}

/// The binary sampler for Field.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldBinarySampler;

impl<F: Field> Distribution<F> for FieldBinarySampler {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        F::new((rng.next_u32() & 0b1).as_into())
    }
}

/// The ternary sampler for Field.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct FieldTernarySampler;

impl<F: Field> Distribution<F> for FieldTernarySampler {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        [F::ZERO, F::ZERO, F::ONE, F::NEG_ONE][(rng.next_u32() & 0b11) as usize]
    }
}

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

impl<F: Field> Distribution<F> for FieldDiscreteGaussianSampler {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> F {
        let mean = self.mean();
        let gaussian = self.gaussian();
        loop {
            let value = gaussian.sample(rng);
            if (value - mean).abs() < self.max_std_dev {
                let round = value.round();
                if round < 0. {
                    return F::new(F::MODULUS_VALUE + (-round).as_into());
                } else {
                    return F::new(round.as_into());
                }
            }
        }
    }
}

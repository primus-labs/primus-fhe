//! This module defines a trait to get some distributions easily.

use std::ops::Rem;

use rand::Rng;
use rand_distr::{Distribution, Normal};

use crate::{AlgebraError, AsFrom, AsInto, Field, Widening, WideningMul, WrappingNeg, WrappingOps};

/// A trait to impl uniform for `Field`.
pub trait UniformBase: Copy {
    /// The type for uniform sample.
    type Sample: Copy
        + AsFrom<Self>
        + AsInto<Self>
        + Widening
        + WrappingOps
        + PartialOrd
        + Rem<Output = Self::Sample>;

    /// Generate a sample for uniform sampler.
    fn gen_sample<R: Rng + ?Sized>(rng: &mut R) -> Self::Sample;
}

macro_rules! uniform_int_impl {
    ($ty:ty, $sample_ty:ident) => {
        impl UniformBase for $ty {
            type Sample = $sample_ty;

            #[inline]
            fn gen_sample<R: Rng + ?Sized>(rng: &mut R) -> Self::Sample {
                rng.gen::<$sample_ty>()
            }
        }
    };
}

uniform_int_impl! { u8, u32 }
uniform_int_impl! { u16, u32 }
uniform_int_impl! { u32, u32 }
uniform_int_impl! { u64, u64 }

/// The uniform sampler for Field.
#[derive(Clone, Copy)]
pub struct FieldUniformSampler<F: Field> {
    /// range
    range: <F::Value as UniformBase>::Sample,
    /// thresh
    thresh: <F::Value as UniformBase>::Sample,
}

impl<F: Field> FieldUniformSampler<F> {
    /// Creates a new [`FieldUniformSampler<F>`].
    #[inline]
    pub fn new() -> Self {
        let range = <F::Value as UniformBase>::Sample::as_from(F::MODULUS_VALUE);
        Self {
            range,
            thresh: range.wrapping_neg() % range,
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
        let hi = loop {
            let (lo, hi) = <F::Value as UniformBase>::gen_sample(rng).widening_mul(self.range);
            if lo >= self.thresh {
                break hi;
            }
        };
        F::new(hi.as_into())
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
        [F::zero(), F::one()][(rng.next_u32() & 0b1) as usize]
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
        [F::zero(), F::zero(), F::one(), F::neg_one()][(rng.next_u32() & 0b11) as usize]
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
                    return F::new(F::MODULUS_VALUE - (-round).as_into());
                } else {
                    return F::new(round.as_into());
                }
            }
        }
    }
}

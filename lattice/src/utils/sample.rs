use std::ops::Sub;

use algebra::AsFrom;
use num_traits::{ConstOne, ConstZero};
use rand::{distributions::Distribution, CryptoRng, Rng};
use rand_distr::Normal;

/// Sample a binary vector whose values are `T`.
pub fn sample_binary_values<T, R>(length: usize, rng: &mut R) -> Vec<T>
where
    T: Copy + ConstZero + AsFrom<u32>,
    R: Rng + CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    let mut iter = v.chunks_exact_mut(32);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = T::as_from(r & 0b1);
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = T::as_from(r & 0b1);
        r >>= 1;
    }
    v
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_ternary_values<T, R>(modulus: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: Copy + ConstZero + ConstOne + Sub<Output = T>,
    R: Rng + CryptoRng,
{
    let s = [T::ZERO, T::ZERO, T::ONE, modulus - T::ONE];
    let mut v = vec![T::ZERO; length];
    let mut iter = v.chunks_exact_mut(16);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = s[(r & 0b11) as usize];
        r >>= 2;
    }
    v
}

/// The gaussian distribution `N(mean, std_dev**2)`.
#[derive(Clone, Copy, Debug)]
pub struct DiscreteGaussian<T: Copy> {
    normal: Normal<f64>,
    max_std_dev: f64,
    modulus: T,
}

impl<T: Copy> DiscreteGaussian<T> {
    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new(
        modulus: T,
        mean: f64,
        std_dev: f64,
    ) -> Result<DiscreteGaussian<T>, algebra::AlgebraError> {
        let max_std_dev = std_dev * 6.0;
        if std_dev < 0. {
            return Err(algebra::AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(normal) => Ok(DiscreteGaussian {
                normal,
                max_std_dev,
                modulus,
            }),
            Err(_) => Err(algebra::AlgebraError::DistributionError),
        }
    }

    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new_with_max_limit(
        modulus: T,
        mean: f64,
        std_dev: f64,
        max_std_dev: f64,
    ) -> Result<DiscreteGaussian<T>, algebra::AlgebraError> {
        if max_std_dev <= std_dev || std_dev < 0. {
            return Err(algebra::AlgebraError::DistributionError);
        }
        match Normal::new(mean, std_dev) {
            Ok(inner) => Ok(DiscreteGaussian {
                normal: inner,
                max_std_dev,
                modulus,
            }),
            Err(_) => Err(algebra::AlgebraError::DistributionError),
        }
    }

    /// Returns the mean (`μ`) of the distribution.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.normal.mean()
    }

    /// Returns the standard deviation (`σ`) of the distribution.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.normal.std_dev()
    }

    /// Returns the max deviation of the distribution.
    #[inline]
    pub fn max_std_dev(&self) -> f64 {
        self.max_std_dev
    }
}

impl<T: Copy> Distribution<T> for DiscreteGaussian<T>
where
    T: AsFrom<f64> + Sub<Output = T>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        let mean = self.normal.mean();
        loop {
            let value = self.normal.sample(rng);
            if (value - mean).abs() < self.max_std_dev {
                let round = value.round();
                if round < 0. {
                    return self.modulus - T::as_from(-value);
                } else {
                    return T::as_from(value);
                }
            }
        }
    }
}

/// The binary sampler.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct BinarySampler;

impl<T> Distribution<T> for BinarySampler
where
    T: AsFrom<u32>,
{
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        T::as_from(rng.next_u32() & 0b1)
    }
}

/// The ternary sampler.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct TernarySampler<T: Copy> {
    neg_one: T,
}

impl<T> TernarySampler<T>
where
    T: Copy + ConstOne + Sub<Output = T>,
{
    /// Creates a new [`TernarySampler`].
    #[inline]
    pub fn new(modulus: T) -> Self {
        Self {
            neg_one: modulus - T::ONE,
        }
    }
}

impl<T: Copy + ConstOne + ConstZero> Distribution<T> for TernarySampler<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        [T::ZERO, T::ZERO, T::ONE, self.neg_one][(rng.next_u32() & 0b11) as usize]
    }
}

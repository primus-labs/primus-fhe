use rand::{CryptoRng, Rng};
use rand_distr::Distribution;

use crate::{
    integer::{Integer, UnsignedInteger},
    AlgebraError,
};

/// Sample a binary vector whose values are `T`.
pub fn sample_binary_values<T, R>(length: usize, rng: &mut R) -> Vec<T>
where
    T: Integer,
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
pub fn sample_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: UnsignedInteger,
    R: Rng + CryptoRng,
{
    let s = [T::ZERO, T::ZERO, T::ONE, minus_one];
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
#[derive(Clone)]
pub enum DiscreteGaussian<T: UnsignedInteger> {
    /// CDTSampler
    Cdt(super::CDTSampler<T>),
    /// UnixCDTSampler
    #[cfg(target_os = "linux")]
    Unix(super::UnixCDTSampler<T>),
    /// DiscreteZiggurat
    Ziggurat(super::DiscreteZiggurat<T>),
}

impl<T: UnsignedInteger> DiscreteGaussian<T> {
    /// Construct, from mean and standard deviation
    ///
    /// Parameters:
    ///
    /// -   mean (`μ`, unrestricted)
    /// -   standard deviation (`σ`, must be finite)
    #[inline]
    pub fn new(
        _mean: f64,
        std_dev: f64,
        modulus_minus_one: T,
    ) -> Result<DiscreteGaussian<T>, AlgebraError> {
        // if std_dev < 0.7 {
        //     Err(AlgebraError::DistributionErr)
        // } else 
        if std_dev < 3.0 {
            #[cfg(target_os = "linux")]
            {
                Ok(DiscreteGaussian::Unix(super::UnixCDTSampler::new(
                    std_dev,
                    6.0,
                    modulus_minus_one,
                )))
            }

            #[cfg(not(target_os = "linux"))]
            Ok(DiscreteGaussian::Cdt(super::CDTSampler::new(
                std_dev,
                6.0,
                modulus_minus_one,
            )))
        } else {
            Ok(DiscreteGaussian::Ziggurat(super::DiscreteZiggurat::new(
                std_dev,
                6.0,
                modulus_minus_one,
            )))
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
        _mean: f64,
        std_dev: f64,
        max_std_dev: f64,
        _modulus_minus_one: T,
    ) -> Result<DiscreteGaussian<T>, AlgebraError> {
        if max_std_dev <= std_dev || std_dev < 0.7 {
            return Err(AlgebraError::DistributionErr);
        }
        unimplemented!()
    }
}

impl<T: UnsignedInteger> Distribution<T> for DiscreteGaussian<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            DiscreteGaussian::Cdt(cdtsampler) => cdtsampler.sample(rng),
            #[cfg(target_os = "linux")]
            DiscreteGaussian::Unix(sampler) => sampler.sample(rng),
            DiscreteGaussian::Ziggurat(discrete_ziggurat) => discrete_ziggurat.sample(rng),
        }
    }
}

/// The binary sampler.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct BinarySampler;

impl<T: Integer> Distribution<T> for BinarySampler {
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
pub struct TernarySampler<T: Integer> {
    minus_one: T,
}

impl<T: Integer> TernarySampler<T> {
    /// Creates a new [`TernarySampler`].
    #[inline]
    pub fn new(minus_one: T) -> Self {
        Self { minus_one }
    }
}

impl<T: Integer> Distribution<T> for TernarySampler<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        [T::ZERO, T::ZERO, T::ONE, self.minus_one][(rng.next_u32() & 0b11) as usize]
    }
}

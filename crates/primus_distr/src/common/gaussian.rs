use primus_integer::FheUint;

use crate::DiscreteGaussian;

/// Sample a vector of `length` values from a discrete Gaussian distribution.
pub fn sample_gaussian_values<T, R>(
    length: usize,
    distr: &DiscreteGaussian<T>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_vec(length, rng)
}

/// Fill `result` with samples from a discrete Gaussian distribution (in-place).
pub fn sample_gaussian_values_to<T, R>(result: &mut [T], distr: &DiscreteGaussian<T>, rng: &mut R)
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_to(result, rng);
}

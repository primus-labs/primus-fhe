use primus_integer::FheInt;
use rand::distr::{Distribution, Uniform};

/// Sample a vector of `length` values from a uniform distribution.
pub fn sample_uniform_values<T, R>(length: usize, distr: &Uniform<T>, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_iter(rng).take(length).collect()
}

/// Fill `result` with samples from a uniform distribution (in-place).
pub fn sample_uniform_values_to<T, R>(result: &mut [T], distr: &Uniform<T>, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .iter_mut()
        .zip(distr.sample_iter(rng))
        .for_each(|(a, b)| *a = b);
}

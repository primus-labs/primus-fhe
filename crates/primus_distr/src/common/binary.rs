use primus_integer::FheInt;
use rand::distr::Bernoulli;

use super::insert_random_values;

/// Sample a binary vector whose values are `T`.
pub fn sample_uniform_binary_values<T, R>(length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_uniform_binary_values_to(&mut v, rng);
    v
}

/// Sample a binary vector whose values are `T`.
pub fn sample_uniform_binary_values_to<T, R>(result: &mut [T], rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let s = [T::ZERO, T::ONE];

    let (chunks, remainder) = result.as_chunks_mut::<32>();
    for chunk in chunks {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b1) as usize];
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in remainder {
        *elem = s[(r & 0b1) as usize];
        r >>= 1;
    }
}

/// Samples binary values with the configured probability of sampling `1`.
///
/// # Panics
///
/// Panics if `one_probability` is not finite or does not belong to `[0, 1]`.
pub fn sample_binary_values_with_probability<T, R>(
    length: usize,
    one_probability: f64,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_binary_values_with_probability_to(&mut result, one_probability, rng);
    result
}

/// Fills a binary slice with the configured probability of sampling `1`.
///
/// # Panics
///
/// Panics before writing if the probability is invalid.
pub fn sample_binary_values_with_probability_to<T, R>(
    result: &mut [T],
    one_probability: f64,
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let distribution = Bernoulli::new(one_probability)
        .expect("binary one probability must be finite and in [0, 1]");
    crate::binary::fill_binary(result, &distribution, rng);
}

/// Samples a binary vector containing exactly `hamming_weight` ones.
///
/// # Panics
///
/// Panics if `hamming_weight` exceeds `length`.
pub fn sample_fixed_hamming_weight_binary_values<T, R>(
    length: usize,
    hamming_weight: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_fixed_hamming_weight_binary_values_to(&mut result, hamming_weight, rng);
    result
}

/// Overwrites a complete logical binary key with exactly `hamming_weight` ones.
///
/// # Panics
///
/// Panics before writing if the weight exceeds the slice length.
pub fn sample_fixed_hamming_weight_binary_values_to<T, R>(
    result: &mut [T],
    hamming_weight: usize,
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    assert!(
        hamming_weight <= result.len(),
        "binary Hamming weight must not exceed the output length"
    );
    let zero_weight = result.len() - hamming_weight;
    let (base, inserted, count) = if hamming_weight <= zero_weight {
        (T::ZERO, T::ONE, hamming_weight)
    } else {
        (T::ONE, T::ZERO, zero_weight)
    };
    result.fill(base);
    insert_random_values(result, result.len() - count, count, inserted, rng);
}

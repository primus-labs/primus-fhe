use primus_integer::{FheInt, Integer};
use rand::distr::{Distribution, Uniform};

use super::insert_random_values;

/// Samples sparse ternary values.
///
/// Values have probabilities `P(0) = 1/2` and `P(1) = P(-1) = 1/4`.
/// `minus_one` encodes `-1`. Uses [`sample_sparse_ternary_values_to`]'s
/// packed random-word order.
#[must_use]
pub fn sample_sparse_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: Integer,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_sparse_ternary_values_to(&mut v, minus_one, rng);
    v
}

/// Fills `result` with sparse ternary values.
///
/// Values have probabilities `P(0) = 1/2` and `P(1) = P(-1) = 1/4`.
/// `minus_one` encodes `-1`.
/// Each `next_u32()` supplies sixteen low-to-high two-bit groups, mapped to
/// `[0, 0, 1, minus_one]`. Consumes exactly `result.len().div_ceil(16)` words;
/// unused high bits are discarded, and empty output consumes no randomness.
pub fn sample_sparse_ternary_values_to<T, R>(result: &mut [T], minus_one: T, rng: &mut R)
where
    T: Integer,
    R: rand::Rng + rand::CryptoRng,
{
    let s = [T::ZERO, T::ZERO, T::ONE, minus_one];

    let (chunks, remainder) = result.as_chunks_mut::<16>();
    for chunk in chunks {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
    if !remainder.is_empty() {
        let mut r = rng.next_u32();
        for elem in remainder {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
}

/// Samples uniformly from `{-1, 0, 1}`.
pub fn sample_uniform_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_uniform_ternary_values_to(&mut result, minus_one, rng);
    result
}

/// Fills `result` uniformly from `{-1, 0, 1}`.
pub fn sample_uniform_ternary_values_to<T, R>(result: &mut [T], minus_one: T, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let values = [minus_one, T::ZERO, T::ONE];
    let mut random = 0;
    let mut remaining_bytes = 0;
    // A uniform byte below 3^5 contains five independent uniform trits.
    // Reject 243..=255, rather than reducing a byte modulo 243 with bias.
    for chunk in result.chunks_mut(5) {
        let mut trits = loop {
            if remaining_bytes == 0 {
                random = rng.next_u32();
                remaining_bytes = 4;
            }
            let byte = random & 0xff;
            random >>= 8;
            remaining_bytes -= 1;
            if byte < 243 {
                break byte;
            }
        };
        for output in chunk {
            *output = values[(trits % 3) as usize];
            trits /= 3;
        }
    }
}

/// Samples ternary values with explicit probabilities for `-1` and `1`.
/// Each probability is rounded down to a multiple of `2^-64`; the total
/// nonzero probability is capped at one to handle floating-point boundary rounding.
///
/// # Panics
///
/// Panics if either probability is invalid or their sum exceeds one.
pub fn sample_ternary_values_with_probabilities<T, R>(
    minus_one: T,
    length: usize,
    minus_one_probability: f64,
    one_probability: f64,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_ternary_values_with_probabilities_to(
        &mut result,
        minus_one,
        minus_one_probability,
        one_probability,
        rng,
    );
    result
}

/// Fills a ternary slice with explicit probabilities of `minus_one` and `1`.
///
/// `minus_one` is the caller's encoding of `-1`.
/// Probabilities use the quantization described by
/// [`sample_ternary_values_with_probabilities`].
///
/// # Panics
///
/// Panics before writing if a probability is invalid or their sum exceeds one.
pub fn sample_ternary_values_with_probabilities_to<T, R>(
    result: &mut [T],
    minus_one: T,
    minus_one_probability: f64,
    one_probability: f64,
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    crate::ternary::TernarySampler::new(minus_one_probability, one_probability)
        .sample_to(result, minus_one, rng);
}

/// Samples exactly `hamming_weight` nonzero coefficients at uniformly selected
/// positions, with independent uniform signs. `minus_one` encodes `-1`.
///
/// # Panics
///
/// Panics if the weight exceeds `length`.
#[must_use]
pub fn sample_fixed_hamming_weight_ternary_values<T, R>(
    minus_one: T,
    length: usize,
    hamming_weight: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut output = vec![T::ZERO; length];
    sample_fixed_hamming_weight_ternary_values_to(&mut output, minus_one, hamming_weight, rng);
    output
}

/// Overwrites a complete logical key with exactly `hamming_weight` nonzero
/// coefficients and independent uniform signs. `minus_one` encodes `-1`.
///
/// # Panics
///
/// Panics before writing or sampling if the weight exceeds the output length.
pub fn sample_fixed_hamming_weight_ternary_values_to<T, R>(
    output: &mut [T],
    minus_one: T,
    hamming_weight: usize,
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    assert!(
        hamming_weight <= output.len(),
        "ternary Hamming weight must not exceed the output length"
    );
    let values = [minus_one, T::ONE];
    if hamming_weight == output.len() {
        for chunk in output.chunks_mut(32) {
            let mut signs = rng.next_u32();
            for out in chunk {
                *out = values[(signs & 1) as usize];
                signs >>= 1;
            }
        }
        return;
    }
    output.fill(T::ZERO);
    let mut signs = 0;
    let mut remaining_signs = 0;
    // Random insertion extends the initially all-zero prefix, as in
    // insert_random_values; the sign of each inserted value is independent.
    for index in output.len() - hamming_weight..output.len() {
        if remaining_signs == 0 {
            signs = rng.next_u32();
            remaining_signs = 32;
        }
        let selected = Uniform::new_inclusive(0, index)
            .expect("nonempty insertion range")
            .sample(rng);
        output[index] = output[selected];
        output[selected] = values[(signs & 1) as usize];
        signs >>= 1;
        remaining_signs -= 1;
    }
}

/// Samples a ternary vector with exact counts of `-1` and `1`.
///
/// # Panics
///
/// Panics if the weights overflow or their sum exceeds `length`.
#[must_use]
pub fn sample_fixed_composition_ternary_values<T, R>(
    minus_one: T,
    length: usize,
    minus_one_weight: usize,
    one_weight: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_fixed_composition_ternary_values_to(
        &mut result,
        minus_one,
        minus_one_weight,
        one_weight,
        rng,
    );
    result
}

/// Overwrites a complete logical ternary key with exact negative/positive weights.
///
/// `minus_one` is the caller's encoding of `-1`.
///
/// # Panics
///
/// Panics before writing if the weights overflow or exceed the slice length.
pub fn sample_fixed_composition_ternary_values_to<T, R>(
    result: &mut [T],
    minus_one: T,
    minus_one_weight: usize,
    one_weight: usize,
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let nonzero_weight = minus_one_weight
        .checked_add(one_weight)
        .expect("ternary Hamming weights must fit in usize");
    assert!(
        nonzero_weight <= result.len(),
        "ternary Hamming weights must not exceed the output length"
    );
    let counts = [result.len() - nonzero_weight, minus_one_weight, one_weight];
    let values = [T::ZERO, minus_one, T::ONE];
    let mut base = 0;
    for index in 1..3 {
        if counts[index] > counts[base] {
            base = index;
        }
    }
    result.fill(values[base]);
    let mut prefix_length = counts[base];
    for index in 0..3 {
        if index != base {
            insert_random_values(result, prefix_length, counts[index], values[index], rng);
            prefix_length += counts[index];
        }
    }
}

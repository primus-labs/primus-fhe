use num_traits::ConstZero;
use primus_integer::{FheInt, FheUint, SignedInteger, UnsignedInteger};
use rand::distr::{Distribution, Uniform};

use super::sample_uniform_binary_values_to;
use crate::SignedDiscreteGaussian;

/// Generates `length` binary values and replicates them across `moduli_count`
/// slots, producing a vector of `length * moduli_count` elements in
/// modulus-major CRT order.
///
/// # Correctness
/// The product `length * moduli_count` must fit in `usize`.
///
/// # Panics
/// Panics if `length` or `moduli_count` is zero; this sampler requires at least
/// one nonempty CRT block.
pub fn sample_crt_uniform_binary_values<T, R>(
    length: usize,
    moduli_count: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_uniform_binary_values_to(&mut result, length, rng);

    result
}

/// Fills `result` with CRT-layout uniform binary values.
///
/// Samples `length` binary values into the first chunk, then copies them
/// into each subsequent chunk of `length` elements.
///
/// # Correctness
/// `result.len()` must be a multiple of `length`. A trailing partial block is
/// left untouched, so callers must establish the complete CRT layout.
///
/// # Panics
/// Panics if `length == 0` or `result.len() < length`. Empty output is not supported.
pub fn sample_crt_uniform_binary_values_to<T, R>(result: &mut [T], length: usize, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let (v, w) = result.split_at_mut(length);

    sample_uniform_binary_values_to(v, rng);

    w.chunks_exact_mut(length)
        .for_each(|s| s.copy_from_slice(v));
}

/// Samples CRT-layout sparse ternary values.
///
/// Each logical value is shared by every modulus component and has
/// probabilities `P(0) = 1/2` and `P(1) = P(-1) = 1/4`.
/// `moduli_minus_one[i]` encodes `-1` in component `i`.
pub fn sample_crt_sparse_ternary_values<T, R>(
    length: usize,
    moduli_minus_one: &[T],
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let moduli_count = moduli_minus_one.len();
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_sparse_ternary_values_to(&mut result, length, moduli_minus_one, rng);

    result
}

/// Fills `result` with CRT-layout sparse ternary values.
///
/// Each logical value is shared by every modulus component and has
/// probabilities `P(0) = 1/2` and `P(1) = P(-1) = 1/4`.
/// `moduli_minus_one[i]` encodes `-1` in component `i`.
///
/// # Correctness
///
/// `result.len()` must equal `length * moduli_minus_one.len()`; this layout
/// requirement is checked only in debug builds. Empty output is supported.
pub fn sample_crt_sparse_ternary_values_to<T, R>(
    result: &mut [T],
    length: usize,
    moduli_minus_one: &[T],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert_eq!(result.len(), moduli_minus_one.len() * length);

    if result.is_empty() {
        return;
    }

    // Keep random words in a small stack tile, then write each CRT limb
    // contiguously. Every limb decodes the same words with its encoding of -1.
    const TILE_LENGTH: usize = 256;
    let mut words = [0u32; TILE_LENGTH / 16];
    for offset in (0..length).step_by(TILE_LENGTH) {
        let tile_length = (length - offset).min(TILE_LENGTH);
        let words = &mut words[..tile_length.div_ceil(16)];
        for word in words.iter_mut() {
            *word = rng.next_u32();
        }
        for (limb, &minus_one) in result.chunks_exact_mut(length).zip(moduli_minus_one) {
            let values = [T::ZERO, T::ZERO, T::ONE, minus_one];
            for (chunk, &word) in limb[offset..offset + tile_length]
                .chunks_mut(16)
                .zip(words.iter())
            {
                let mut random = word;
                for out in chunk {
                    *out = values[(random & 3) as usize];
                    random >>= 2;
                }
            }
        }
    }
}

/// Samples a uniform vector in modulus-major CRT layout.
pub fn sample_crt_uniform_values<T, R>(
    poly_length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; poly_length * uniform_distrs.len()];

    sample_crt_uniform_values_to(&mut result, poly_length, uniform_distrs, rng);

    result
}

/// Fills a slice with uniform samples in modulus-major CRT layout.
///
/// In debug builds, this function checks that `poly_length` is nonzero and
/// that `result.len()` equals `poly_length * uniform_distrs.len()`.
pub fn sample_crt_uniform_values_to<T, R>(
    result: &mut [T],
    poly_length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert!(poly_length > 0, "CRT polynomial length must be nonzero");
    debug_assert_eq!(
        result.len(),
        poly_length * uniform_distrs.len(),
        "CRT uniform output length must equal polynomial length times the distribution count"
    );

    result
        .chunks_exact_mut(poly_length)
        .zip(uniform_distrs)
        .for_each(|(s, u)| {
            s.iter_mut()
                .zip(u.sample_iter(&mut *rng))
                .for_each(|(a, b)| {
                    *a = b;
                });
        });
}

/// Samples a Gaussian vector in modulus-major CRT layout.
///
/// Every modulus must canonically encode the complete truncated support. This
/// precondition is not checked and must be established by the caller's
/// parameter construction.
pub fn sample_crt_gaussian_values<T, R>(
    length: usize,
    moduli: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    let moduli_count = moduli.len();
    let mut result = vec![T::ZERO; length * moduli_count];
    sample_crt_gaussian_values_to(&mut result, length, moduli, gaussian, rng);

    result
}

/// Fills a slice with Gaussian samples in modulus-major CRT layout.
///
/// Every modulus must canonically encode the complete truncated support. This
/// precondition is not checked and must be established by the caller's
/// parameter construction.
///
/// In debug builds, this function checks that `length` is nonzero and that
/// `result.len()` equals `length * moduli.len()`.
pub fn sample_crt_gaussian_values_to<T, R>(
    result: &mut [T],
    length: usize,
    moduli: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert!(length > 0, "CRT polynomial length must be nonzero");
    debug_assert_eq!(
        result.len(),
        length * moduli.len(),
        "CRT Gaussian output length must equal length times the modulus count"
    );
    if result.is_empty() {
        return;
    }

    for coefficient in 0..length {
        let sample = gaussian.sample(rng);
        if sample >= <<T as UnsignedInteger>::SignedInteger as ConstZero>::ZERO {
            let residue: T = sample.cast_to_unsigned();
            for value in result.iter_mut().skip(coefficient).step_by(length) {
                *value = residue;
            }
        } else {
            for (value, &modulus) in result
                .iter_mut()
                .skip(coefficient)
                .step_by(length)
                .zip(moduli)
            {
                *value = <T as UnsignedInteger>::wrapping_add_signed(modulus, sample);
            }
        }
    }
}

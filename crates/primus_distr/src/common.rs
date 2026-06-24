use std::slice::IterMut;

use itertools::Itertools;
use num_traits::ConstZero;
use primus_integer::{AsInto, FheInt, FheUint, UnsignedInteger};
use rand::distr::{Distribution, Uniform};

use crate::{DiscreteGaussian, SignedDiscreteGaussian};

/// Sample a binary vector whose values are `T`.
pub fn sample_binary_values<T, R>(length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_binary_values_to(&mut v, rng);
    v
}

/// Sample a binary vector whose values are `T`.
pub fn sample_binary_values_to<T, R>(result: &mut [T], rng: &mut R)
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

/// Sample a ternary vector whose values are `T`.
pub fn sample_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_ternary_values_inplace(&mut v, minus_one, rng);
    v
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_ternary_values_inplace<T, R>(result: &mut [T], minus_one: T, rng: &mut R)
where
    T: FheInt,
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
    let mut r = rng.next_u32();
    for elem in remainder {
        *elem = s[(r & 0b11) as usize];
        r >>= 2;
    }
}

/// Sample a vector of `length` values from a uniform distribution.
pub fn sample_uniform_values<T, R>(length: usize, distr: &Uniform<T>, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_iter(rng).take(length).collect()
}

/// Fill `result` with samples from a uniform distribution (in-place).
pub fn sample_uniform_values_inplace<T, R>(result: &mut [T], distr: &Uniform<T>, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .iter_mut()
        .zip(distr.sample_iter(rng))
        .for_each(|(a, b)| *a = b);
}

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
    distr.sample_iter(rng).take(length).collect()
}

/// Fill `result` with samples from a discrete Gaussian distribution (in-place).
pub fn sample_gaussian_values_inplace<T, R>(
    result: &mut [T],
    distr: &DiscreteGaussian<T>,
    rng: &mut R,
) where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .iter_mut()
        .zip(distr.sample_iter(rng))
        .for_each(|(a, b)| *a = b);
}

/// Sample a CRT-layout binary vector.
///
/// Generates `length` binary values and replicates them across `moduli_count`
/// slots, producing a vector of `length * moduli_count` elements in
/// CRT-interleaved order.
pub fn sample_crt_binary_values<T, R>(length: usize, moduli_count: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_binary_values_inplace(&mut result, length, rng);

    result
}

/// Fill `result` with CRT-layout binary values (in-place).
///
/// Samples `length` binary values into the first chunk, then copies them
/// into each subsequent chunk of `length` elements.
pub fn sample_crt_binary_values_inplace<T, R>(result: &mut [T], length: usize, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let (v, w) = result.split_at_mut(length);

    sample_binary_values_to(v, rng);

    w.chunks_exact_mut(length)
        .for_each(|s| s.copy_from_slice(v));
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_crt_ternary_values<T, R>(length: usize, moduli_minus_one: &[T], rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let moduli_count = moduli_minus_one.len();
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_ternary_values_inplace(&mut result, length, moduli_minus_one, rng);

    result
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_crt_ternary_values_inplace<T, R>(
    result: &mut [T],
    length: usize,
    moduli_minus_one: &[T],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert_eq!(result.len(), moduli_minus_one.len() * length);
    let mut iters: Vec<IterMut<'_, T>> = result
        .chunks_exact_mut(length)
        .map(|s| s.iter_mut())
        .collect();

    'outer: loop {
        let mut r = rng.next_u32();
        for _ in 0..16 {
            match r & 0b11 {
                0 | 1 => {
                    for iter in iters.iter_mut() {
                        if let Some(value) = iter.next() {
                            *value = T::ZERO;
                        } else {
                            break 'outer;
                        }
                    }
                }
                2 => {
                    for iter in iters.iter_mut() {
                        if let Some(value) = iter.next() {
                            *value = T::ONE;
                        } else {
                            break 'outer;
                        }
                    }
                }
                3 => {
                    for (iter, &modulus_minus_one) in iters.iter_mut().zip(moduli_minus_one) {
                        if let Some(value) = iter.next() {
                            *value = modulus_minus_one;
                        } else {
                            break 'outer;
                        }
                    }
                }
                _ => unreachable!(),
            }
            r >>= 2;
        }
    }
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values<T, R>(
    length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length * uniform_distrs.len()];

    sample_crt_uniform_values_inplace(&mut result, length, uniform_distrs, rng);

    result
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values_inplace<T, R>(
    result: &mut [T],
    length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .chunks_exact_mut(length)
        .zip_eq(uniform_distrs)
        .for_each(|(s, u)| {
            s.iter_mut()
                .zip(u.sample_iter(&mut *rng))
                .for_each(|(a, b)| {
                    *a = b;
                });
        });
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values_iter_mut<T, R>(
    iters: Vec<IterMut<'_, T>>,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    iters.into_iter().zip(uniform_distrs).for_each(|(s, u)| {
        s.zip(u.sample_iter(&mut *rng)).for_each(|(a, b)| {
            *a = b;
        });
    });
}

/// Sample a gaussian vector whose values are `T`.
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
    let bound: f64 = 24.0 * gaussian.standard_deviation();
    let bound: T = bound.as_into();
    for modulus in moduli {
        assert!(bound < *modulus);
    }

    let moduli_count = moduli.len();
    let mut result = vec![T::ZERO; length * moduli_count];

    let mut iters: Vec<IterMut<'_, T>> = result
        .chunks_exact_mut(length)
        .map(|s| s.iter_mut())
        .collect();

    'outer: loop {
        let r = gaussian.sample(rng);
        if r >= <<T as UnsignedInteger>::SignedInteger as ConstZero>::ZERO {
            let t: T = <T as UnsignedInteger>::cast_from_signed(r);
            for iter in iters.iter_mut() {
                if let Some(value) = iter.next() {
                    *value = t;
                } else {
                    break 'outer;
                }
            }
        } else {
            for (iter, &modulus) in iters.iter_mut().zip(moduli) {
                if let Some(value) = iter.next() {
                    *value = <T as UnsignedInteger>::wrapping_add_signed(modulus, r);
                } else {
                    break 'outer;
                }
            }
        }
    }

    result
}

/// Sample a gaussian vector whose values are `T`.
pub fn sample_crt_gaussian_values_inplace<T, R>(
    result: &mut [T],
    length: usize,
    moduli_value: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    let iters: Vec<IterMut<'_, T>> = result
        .chunks_exact_mut(length)
        .map(|s| s.iter_mut())
        .collect();
    sample_crt_gaussian_values_iter_mut(iters, moduli_value, gaussian, rng);
}

/// Sample a gaussian vector whose values are `T`.
pub fn sample_crt_gaussian_values_iter_mut<T, R>(
    mut iters: Vec<IterMut<'_, T>>,
    moduli_value: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    loop {
        let r = gaussian.sample(rng);
        if r >= <<T as UnsignedInteger>::SignedInteger as ConstZero>::ZERO {
            let t: T = <T as UnsignedInteger>::cast_from_signed(r);
            for iter in iters.iter_mut() {
                if let Some(value) = iter.next() {
                    *value = t;
                } else {
                    return;
                }
            }
        } else {
            for (iter, &modulus) in iters.iter_mut().zip(moduli_value) {
                if let Some(value) = iter.next() {
                    *value = <T as UnsignedInteger>::wrapping_add_signed(modulus, r);
                } else {
                    return;
                }
            }
        }
    }
}

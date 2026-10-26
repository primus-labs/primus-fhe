//! Setup-only exact negacyclic products in the native coefficient ring.

use primus_integer::{AsInto, FheUint, SignedInteger};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_reduce::{Reduce, ReduceMul, ReduceNeg, ReduceSub, TryReduceInv};
use primus_shape::PolyLength;
use zeroize::Zeroizing;

use super::GlweSecretKey;

// Each p-1 is divisible by 2^19, covering every supported 2N-th root.
const PRIMES: [u64; 2] = [1_125_899_886_395_393, 1_125_899_902_124_033];
const CRT_PRODUCT: u128 = PRIMES[0] as u128 * PRIMES[1] as u128;

const _: () = {
    assert!(PRIMES[0] < PRIMES[1]);
    assert!(CRT_PRODUCT < i128::MAX as u128);
    assert!((PRIMES[0] - 1).is_multiple_of(2 * primus_shape::MAX_POLY_LENGTH as u64));
    assert!((PRIMES[1] - 1).is_multiple_of(2 * primus_shape::MAX_POLY_LENGTH as u64));
    assert!(CRT_PRODUCT > 2 * primus_shape::MAX_POLY_LENGTH as u128 * u64::MAX as u128);
};

/// The supplied coefficients exceed the caller's public magnitude bound.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SecretMagnitudeError;

/// Exact products bound to one borrowed coefficient secret, with erased scratch.
///
/// Each mask polynomial is restored separately before native accumulation, so
/// the CRT capacity bound is independent of GLWE rank. Setup chooses NTT/CRT or
/// wrapping schoolbook using only the declared public bound, never an observed
/// secret norm or support. This does not establish constant-time key generation.
pub(crate) struct ExactSecretProduct<'key, T: FheUint> {
    secret: &'key GlweSecretKey<T>,
    ntt: Option<AuxiliaryNttProduct>,
}

impl<'key, T: FheUint> ExactSecretProduct<'key, T> {
    /// Checks the complete secret against an inclusive public bound before setup.
    /// No distribution, fixed-weight provenance or Fourier precision is certified.
    /// For unrestricted imported coefficients, use `2^(T::BITS-1)` as the bound.
    pub(crate) fn try_new(
        secret: &'key GlweSecretKey<T>,
        maximum_magnitude: T,
    ) -> Result<Self, SecretMagnitudeError> {
        // Scan the entire key without reporting a coefficient, index or norm.
        let within_bound = secret.as_slice().iter().fold(true, |valid, &coefficient| {
            valid & (coefficient.unsigned_abs() <= maximum_magnitude)
        });
        if !within_bound {
            return Err(SecretMagnitudeError);
        }
        let magnitude: u128 = maximum_magnitude.as_into();
        let ntt = (magnitude <= crt_magnitude_limit::<T>(secret.poly_length()))
            .then(|| AuxiliaryNttProduct::new(secret));
        Ok(Self { secret, ntt })
    }

    /// Adds `input * secret[component]` modulo `X^N+1` and `2^T::BITS` to `acc`.
    /// Caller has validated complete N-element input/accumulator buffers and a
    /// component index below the prepared rank. Existing accumulator values are
    /// retained, all scratch is overwritten, and no allocation occurs here.
    pub(crate) fn add_product_assign(&mut self, input: &[T], component: usize, acc: &mut [T]) {
        let n = self.secret.poly_length().get();
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(acc.len(), n);
        debug_assert!(component < self.secret.dimension().get());
        if let Some(ntt) = &mut self.ntt {
            ntt.add_product_assign(input, component, acc);
        } else {
            let secret = &self.secret.as_slice()[component * n..(component + 1) * n];
            add_schoolbook_product_assign(input, secret, acc);
        }
    }
}

/// Ensures `P > 2*(2^w-1)*N*H` without multiplying by a potentially large H.
/// Built-in FHE words are at most 64 bits; 2*MAX*N fits u128 for every PolyLength.
fn crt_magnitude_limit<T: FheUint>(poly_length: PolyLength) -> u128 {
    let native_max: u128 = T::MAX.as_into();
    (CRT_PRODUCT - 1) / (2 * native_max * poly_length.get() as u128)
}

/// Two auxiliary fields restore one signed integer convolution at a time.
/// Tables contain only public data; transformed secrets and product scratch
/// erase on drop/unwind.
struct AuxiliaryNttProduct {
    tables: [U64NttTable; 2],
    secrets: [Zeroizing<Vec<u64>>; 2],
    scratch: [Zeroizing<Vec<u64>>; 2],
    inverse: u64,
}

impl AuxiliaryNttProduct {
    /// Caller established the public capacity bound and checked every coefficient.
    fn new<T: FheUint>(secret: &GlweSecretKey<T>) -> Self {
        let n = secret.poly_length();
        let tables = PRIMES.map(|p| U64NttTable::new(n, BarrettModulus::new(p)).unwrap());
        let secrets = std::array::from_fn(|i| {
            let modulus = BarrettModulus::new(PRIMES[i]);
            // Establish an erasing owner before writing secret-dependent values.
            let mut values = Zeroizing::new(vec![0; secret.as_slice().len()]);
            for (coefficients, transformed) in secret.iter().zip(values.chunks_exact_mut(n.get())) {
                for (out, &coefficient) in transformed.iter_mut().zip(coefficients) {
                    let signed: i64 = coefficient.as_into();
                    let magnitude = modulus.reduce(signed.unsigned_abs());
                    *out = if signed < 0 {
                        modulus.reduce_neg(magnitude)
                    } else {
                        magnitude
                    };
                }
                tables[i].transform_slice(transformed);
            }
            values
        });
        Self {
            tables,
            secrets,
            scratch: std::array::from_fn(|_| Zeroizing::new(vec![0; n.get()])),
            inverse: BarrettModulus::new(PRIMES[1])
                .try_reduce_inv(PRIMES[0])
                .unwrap(),
        }
    }

    /// Uses the already validated component and buffers; restores each coefficient
    /// before native accumulation rather than summing rank products in the CRT ring.
    fn add_product_assign<T: FheUint>(&mut self, input: &[T], component: usize, acc: &mut [T]) {
        let n = input.len();
        for (i, &prime) in PRIMES.iter().enumerate() {
            let modulus = BarrettModulus::new(prime);
            for (out, &value) in self.scratch[i].iter_mut().zip(input) {
                let value: u64 = value.as_into();
                *out = modulus.reduce(value);
            }
            self.tables[i].transform_slice(&mut self.scratch[i]);
            let secret = &self.secrets[i][component * n..(component + 1) * n];
            for (out, &s) in self.scratch[i].iter_mut().zip(secret) {
                *out = modulus.reduce_mul(*out, s);
            }
            self.tables[i].inverse_transform_slice(&mut self.scratch[i]);
        }
        let modulus = BarrettModulus::new(PRIMES[1]);
        for ((out, &r0), &r1) in acc
            .iter_mut()
            .zip(self.scratch[0].iter())
            .zip(self.scratch[1].iter())
        {
            // r0 < p0 < p1 makes both inputs canonical for the p1 subtraction.
            let t = modulus.reduce_mul(modulus.reduce_sub(r1, r0), self.inverse);
            let x = r0 as u128 + PRIMES[0] as u128 * t as u128;
            let centered = if x > CRT_PRODUCT / 2 {
                x as i128 - CRT_PRODUCT as i128
            } else {
                x as i128
            };
            // CRT_PRODUCT fits i128. Retain the low w bits, including negatives;
            // a checked narrowing conversion would not implement native reduction.
            *out = out.wrapping_add((centered as u64).as_into());
        }
    }
}

/// O(N²) exact fallback for public ranges beyond the two-prime CRT capacity.
/// Fixed loops include zero secret coefficients. Splitting at the public wrap
/// position keeps sign selection outside the coefficient loops; neither support
/// nor coefficient signs select an optimized path. No scratch is allocated.
fn add_schoolbook_product_assign<T: FheUint>(
    input: &[T],
    secret: &[T::SignedInteger],
    acc: &mut [T],
) {
    let n = input.len();
    for (i, &a) in input.iter().enumerate() {
        let (wrapped, ordinary) = acc.split_at_mut(i);
        for (out, &s) in ordinary.iter_mut().zip(&secret[..n - i]) {
            *out = out.wrapping_add(a.wrapping_mul(s.cast_to_unsigned()));
        }
        for (out, &s) in wrapped.iter_mut().zip(&secret[n - i..]) {
            *out = out.wrapping_sub(a.wrapping_mul(s.cast_to_unsigned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GlweDimension, GlweSize, SecretKeyDistr};
    use num_traits::ConstZero;
    use primus_integer::ConstBounded;

    /// Gather each output coefficient independently; the kernels scatter products.
    fn oracle<T: FheUint>(input: &[T], secret: &[T::SignedInteger], acc: &[T]) -> Vec<T> {
        let n = input.len();
        (0..n)
            .map(|degree| {
                secret.iter().enumerate().fold(acc[degree], |sum, (j, &s)| {
                    let i = (degree + n - j) & (n - 1);
                    let product = input[i].wrapping_mul(s.cast_to_unsigned());
                    if i + j < n {
                        sum.wrapping_add(product)
                    } else {
                        sum.wrapping_sub(product)
                    }
                })
            })
            .collect()
    }

    /// Native endpoints, nonzero accumulation and repeated use isolate word
    /// reduction and scratch reuse from any encryption/FFT rounding or RNG.
    fn check<T: FheUint>(secret: Vec<T::SignedInteger>, bound: T, uses_ntt: bool) {
        let n = PolyLength::new(32);
        let size = GlweSize::new(GlweDimension::new(secret.len() / n.get()), n);
        let key = GlweSecretKey::new(
            secret,
            size,
            SecretKeyDistr::Gaussian {
                standard_deviation: 1.0,
            },
        );
        let mut product = ExactSecretProduct::try_new(&key, bound).unwrap();
        assert_eq!(product.ntt.is_some(), uses_ntt);
        let half = T::ONE << (T::BITS - 1);
        let edges = [T::ZERO, T::ONE, T::MAX, half.wrapping_sub(T::ONE), half];
        let mut input: Vec<_> = (0..n.get()).map(|i| edges[i % edges.len()]).collect();
        let mut acc: Vec<_> = (0..n.get()).map(|i| edges[(i + 2) % edges.len()]).collect();
        for _ in 0..2 {
            for (component, secret) in key.iter().enumerate() {
                let expected = oracle(&input, secret, &acc);
                product.add_product_assign(&input, component, &mut acc);
                assert_eq!(acc, expected);
            }
            input.rotate_left(3);
        }
    }

    fn small_rank_two<T: FheUint>() {
        let mut secret: Vec<_> = (0..64)
            .map(|i| {
                let value: T::SignedInteger = [-3i64, -1, 0, 1, 3][i % 5].as_into();
                value
            })
            .collect();
        // Exercise a padded target without using its observed support for setup.
        secret[41..].fill(T::SignedInteger::ZERO);
        check::<T>(secret, 3u64.as_into(), true);
    }

    #[test]
    fn crt_accumulation_matches_oracle_for_all_native_words_and_rank_two() {
        small_rank_two::<u16>();
        small_rank_two::<u32>();
        small_rank_two::<u64>();
    }

    fn full_signed_range<T: FheUint>(uses_ntt: bool) {
        let edges = [
            T::SignedInteger::MIN,
            T::SignedInteger::MAX,
            (-1i64).as_into(),
            T::SignedInteger::ZERO,
        ];
        let secret = (0..32).map(|i| edges[i % edges.len()]).collect();
        check::<T>(secret, T::ONE << (T::BITS - 1), uses_ntt);
    }

    #[test]
    fn full_signed_ranges_use_crt_for_narrow_words_and_exact_fallback_for_u64() {
        let maximum_length = PolyLength::new(primus_shape::MAX_POLY_LENGTH);
        assert!(crt_magnitude_limit::<u16>(maximum_length) >= 1 << 15);
        assert!(crt_magnitude_limit::<u32>(maximum_length) >= 1 << 31);
        full_signed_range::<u16>(true);
        full_signed_range::<u32>(true);
        full_signed_range::<u64>(false);
    }

    #[test]
    fn public_crt_capacity_boundary_preserves_both_centered_signs() {
        let n = PolyLength::new(32);
        let limit = crt_magnitude_limit::<u64>(n) as u64;
        let mut secret = vec![limit as i64; n.get()];
        secret.extend(vec![-(limit as i64); n.get()]);
        check::<u64>(secret.clone(), limit, true);
        check::<u64>(secret, limit + 1, false);

        // Reach the positive/negative integer bound at degree N-1, near P/2.
        let size = GlweSize::new(GlweDimension::new(2), n);
        let coefficients = [vec![limit as i64; n.get()], vec![-(limit as i64); n.get()]].concat();
        let key = GlweSecretKey::<u64>::new(coefficients, size, SecretKeyDistr::UniformTernary);
        let mut product = ExactSecretProduct::try_new(&key, limit).unwrap();
        for (component, secret) in key.iter().enumerate() {
            let mut acc = vec![0; n.get()];
            let input = vec![u64::MAX; n.get()];
            let expected = oracle(&input, secret, &acc);
            product.add_product_assign(&input, component, &mut acc);
            assert_eq!(acc, expected);
        }
    }

    #[test]
    fn magnitude_check_handles_signed_minimum_and_zero_bound() {
        let n = PolyLength::new(32);
        let size = GlweSize::new(GlweDimension::new(1), n);
        let key =
            GlweSecretKey::<u64>::new(vec![i64::MIN; n.get()], size, SecretKeyDistr::UniformBinary);
        assert!(ExactSecretProduct::try_new(&key, (1 << 63) - 1).is_err());
        assert!(ExactSecretProduct::try_new(&key, 1 << 63).is_ok());
        let key = GlweSecretKey::<u64>::new(vec![0; n.get()], size, SecretKeyDistr::UniformBinary);
        let mut product = ExactSecretProduct::try_new(&key, 0).unwrap();
        let mut acc = vec![u64::MAX; n.get()];
        product.add_product_assign(&vec![u64::MAX; n.get()], 0, &mut acc);
        assert_eq!(acc, vec![u64::MAX; n.get()]);
        // The same zero secret still takes the public full-range fallback.
        assert!(
            ExactSecretProduct::try_new(&key, u64::MAX)
                .unwrap()
                .ntt
                .is_none()
        );
    }
}

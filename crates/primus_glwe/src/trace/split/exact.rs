//! Setup-only exact native convolution for a rank-one {-1,0,1} secret.
use primus_fft::TorusFftValue;
use primus_integer::AsInto;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_reduce::{Reduce, ReduceMul, ReduceSub, TryReduceInv};
use primus_shape::PolyLength;
use zeroize::Zeroizing;

// Both primes have 2^18 | (p-1), supporting every valid PolyLength.
// Their product exceeds 2*N*(2^64-1), even at the maximum supported N.
const PRIMES: [u64; 2] = [1_125_899_886_395_393, 1_125_899_902_124_033];

const _: () = {
    assert!((PRIMES[0] - 1).is_multiple_of(2 * primus_shape::MAX_POLY_LENGTH as u64));
    assert!((PRIMES[1] - 1).is_multiple_of(2 * primus_shape::MAX_POLY_LENGTH as u64));
    assert!(
        PRIMES[0] as u128 * PRIMES[1] as u128
            > 2 * primus_shape::MAX_POLY_LENGTH as u128 * u64::MAX as u128
    );
};

/// Two auxiliary fields recover the signed integer product before native reduction.
/// Secret transforms and products are erased when this generation state is dropped.
pub(super) struct ExactSecretProduct {
    tables: [U64NttTable; 2],
    secrets: [Zeroizing<Vec<u64>>; 2],
    scratch: [Zeroizing<Vec<u64>>; 2],
    inverse: u64,
    product: u128,
}
impl ExactSecretProduct {
    /// Caller has checked rank one, native u64 and ternary coefficient bounds.
    pub(super) fn new<T: TorusFftValue>(secret: &[T::SignedInteger], n: PolyLength) -> Self {
        let product = PRIMES[0] as u128 * PRIMES[1] as u128;
        let tables = PRIMES.map(|p| U64NttTable::new(n, BarrettModulus::new(p)).unwrap());
        let secrets = std::array::from_fn(|i| {
            let mut values = Zeroizing::new(
                secret
                    .iter()
                    .map(|&s| {
                        let s: i64 = s.as_into();
                        if s < 0 {
                            PRIMES[i] - s.unsigned_abs()
                        } else {
                            s as u64
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            tables[i].transform_slice(&mut values);
            values
        });
        Self {
            tables,
            secrets,
            scratch: std::array::from_fn(|_| Zeroizing::new(vec![0; n.get()])),
            inverse: BarrettModulus::new(PRIMES[1])
                .try_reduce_inv(PRIMES[0])
                .unwrap(),
            product,
        }
    }

    /// Input/output are complete native polynomials of the prepared length.
    pub(super) fn apply<T: TorusFftValue>(&mut self, input: &[T], output: &mut [T]) {
        for (i, &prime) in PRIMES.iter().enumerate() {
            let modulus = BarrettModulus::new(prime);
            for (out, &v) in self.scratch[i].iter_mut().zip(input) {
                let value: u64 = v.as_into();
                *out = modulus.reduce(value);
            }
            self.tables[i].transform_slice(&mut self.scratch[i]);
            for (out, &s) in self.scratch[i].iter_mut().zip(self.secrets[i].iter()) {
                *out = modulus.reduce_mul(*out, s);
            }
            self.tables[i].inverse_transform_slice(&mut self.scratch[i]);
        }
        let modulus = BarrettModulus::new(PRIMES[1]);
        for ((out, &r0), &r1) in output
            .iter_mut()
            .zip(self.scratch[0].iter())
            .zip(self.scratch[1].iter())
        {
            let t = modulus.reduce_mul(modulus.reduce_sub(r1, r0), self.inverse);
            let x = r0 as u128 + PRIMES[0] as u128 * t as u128;
            let centered = if x > self.product / 2 {
                x as i128 - self.product as i128
            } else {
                x as i128
            };
            *out = (centered as u64).as_into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn centered_crt_matches_signed_schoolbook_at_native_edges() {
        let n = PolyLength::new(32);
        let secret: Vec<i64> = (0..n.get()).map(|i| [-1, 0, 1][i % 3]).collect();
        let input: Vec<u64> = (0..n.get())
            .map(|i| [0, 1, u64::MAX, (1 << 63) - 1, 1 << 63][i % 5])
            .collect();
        let mut expected = vec![0u64; n.get()];
        for (i, &a) in input.iter().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let p = a.wrapping_mul(s as u64);
                let k = (i + j) % n.get();
                expected[k] = if i + j < n.get() {
                    expected[k].wrapping_add(p)
                } else {
                    expected[k].wrapping_sub(p)
                };
            }
        }
        let mut actual = vec![0; n.get()];
        ExactSecretProduct::new::<u64>(&secret, n).apply(&input, &mut actual);
        assert_eq!(actual, expected);
    }
}

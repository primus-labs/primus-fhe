//! Exact wrapping polynomial arithmetic for native NTRU key preparation.

use primus_integer::FheUint;
use primus_shape::PolyLength;
use zeroize::{Zeroize, Zeroizing};

use crate::NtruError;

/// Reusable scratch for a full native negacyclic product. The recursive
/// Karatsuba temporaries share one buffer and are erased with their owner.
pub(crate) struct NativeProductWorkspace(Zeroizing<Vec<u64>>);

impl NativeProductWorkspace {
    pub(crate) fn new(length: PolyLength) -> Self {
        // N input words, 2N product words, and at most 4N recursive scratch.
        Self(Zeroizing::new(vec![0; 7 * length.get()]))
    }

    pub(crate) fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
        self.0.spare_capacity_mut().zeroize();
    }

    pub(crate) fn multiply_assign<T: FheUint>(&mut self, left: &[u64], right: &mut [T]) {
        let n = left.len();
        debug_assert_eq!(right.len(), n);
        let (input, rest) = self.0.split_at_mut(n);
        let (product, scratch) = rest.split_at_mut(2 * n);
        for (out, &value) in input.iter_mut().zip(right.iter()) {
            *out = value.as_into();
        }
        convolution_to(left, input, product, scratch);
        let (low, high) = product.split_at(n);
        for (out, (&low, &high)) in right.iter_mut().zip(low.iter().zip(high)) {
            *out = T::as_from(low.wrapping_sub(high));
        }
    }
}

/// Computes a power-of-two native inverse using only wrapping products.
/// Reducing to a smaller word width is valid since reduction modulo 2^BITS
/// is a ring homomorphism.
pub(crate) fn inverse(
    secret: &[u64],
    length: PolyLength,
    bits: u32,
) -> Result<Zeroizing<Vec<u64>>, NtruError> {
    if secret.iter().fold(0, |sum, &value| sum ^ (value & 1)) == 0 {
        return Err(NtruError::NonInvertibleSecretKey);
    }
    let n = length.get();
    let mut workspace = NativeProductWorkspace::new(length);
    // In F2[X]/((X+1)^N), f^N=f(1)=1. Repeated Frobenius squares
    // compute f^(N-1), the inverse modulo two.
    let mut power = Zeroizing::new(secret.iter().map(|&value| value & 1).collect::<Vec<_>>());
    let mut squared = Zeroizing::new(vec![0; n]);
    let mut result = Zeroizing::new(vec![0; n]);
    result[0] = 1;
    for _ in 0..length.log_n() {
        workspace.multiply_assign(&power, result.as_mut_slice());
        for value in result.iter_mut() {
            *value &= 1;
        }
        squared.fill(0);
        for (index, &value) in power.iter().enumerate() {
            squared[(2 * index) & (n - 1)] ^= value;
        }
        std::mem::swap(&mut power, &mut squared);
    }
    // Newton doubles valid low bits with each f^-1 <- f^-1 (2 - f f^-1).
    let mut correction = Zeroizing::new(vec![0u64; n]);
    for _ in 0..bits.ilog2() {
        correction.copy_from_slice(&result);
        workspace.multiply_assign(secret, correction.as_mut_slice());
        for value in correction.iter_mut() {
            *value = value.wrapping_neg();
        }
        correction[0] = correction[0].wrapping_add(2);
        workspace.multiply_assign(&correction, result.as_mut_slice());
    }
    Ok(result)
}

/// Computes a linear product in Z/(2^64). Negacyclic reduction follows at
/// the owning boundary. Each recursive level needs 2N words of scratch.
fn convolution_to(left: &[u64], right: &[u64], output: &mut [u64], scratch: &mut [u64]) {
    let n = left.len();
    if n <= 32 {
        output.fill(0);
        for (index, &left) in left.iter().enumerate() {
            for (output, &right) in output[index..][..n].iter_mut().zip(right) {
                *output = output.wrapping_add(left.wrapping_mul(right));
            }
        }
        return;
    }

    let h = n / 2;
    let (left_low, left_high) = left.split_at(h);
    let (right_low, right_high) = right.split_at(h);
    let (low, high) = output.split_at_mut(n);
    convolution_to(left_low, right_low, low, scratch);
    convolution_to(left_high, right_high, high, scratch);

    let (left_sum, rest) = scratch.split_at_mut(h);
    let (right_sum, rest) = rest.split_at_mut(h);
    let (cross, child) = rest.split_at_mut(n);
    for ((sum, &a), &b) in left_sum.iter_mut().zip(left_low).zip(left_high) {
        *sum = a.wrapping_add(b);
    }
    for ((sum, &a), &b) in right_sum.iter_mut().zip(right_low).zip(right_high) {
        *sum = a.wrapping_add(b);
    }
    convolution_to(left_sum, right_sum, cross, child);
    for ((cross, &low), &high) in cross.iter_mut().zip(low.iter()).zip(high.iter()) {
        *cross = cross.wrapping_sub(low).wrapping_sub(high);
    }
    for (output, &cross) in output[h..][..n].iter_mut().zip(cross.iter()) {
        *output = output.wrapping_add(cross);
    }
}

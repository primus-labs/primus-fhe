//! Broadcast Shoup kernels for polynomial-sized slices.
//!
//! The factor must match the modulus, which is below 2^63. Multiplication
//! accepts a full-width rhs; multiply-add requires a canonical accumulator.

use super::ShoupFactor;
use primus_integer::FheUint;

#[inline]
fn available<T: FheUint>(len: usize) -> bool {
    if std::any::TypeId::of::<T>() != std::any::TypeId::of::<u64>() || len < 32 {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[inline]
pub(super) fn try_mul_assign<T: FheUint>(
    factor: ShoupFactor<T>,
    values: &mut [T],
    modulus: T,
) -> bool {
    if !available::<T>(values.len()) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: available proves T is exactly u64 and checks the kernel's CPU
    // features. The cast preserves the slice's length and exclusive borrow.
    unsafe {
        let values = std::slice::from_raw_parts_mut(values.as_mut_ptr().cast(), values.len());
        avx512::mul_assign(
            ShoupFactor::from_raw(factor.value().as_into(), factor.quotient().as_into()),
            values,
            modulus.as_into(),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (factor, values, modulus);
    true
}

#[inline]
pub(super) fn try_mul_to<T: FheUint>(
    factor: ShoupFactor<T>,
    input: &[T],
    output: &mut [T],
    modulus: T,
) -> bool {
    debug_assert_eq!(input.len(), output.len());
    if !available::<T>(input.len()) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: exact type and CPU features are checked above. The casts preserve
    // lengths and disjoint borrows; full chunks bound each vector load/store.
    unsafe {
        let input = std::slice::from_raw_parts(input.as_ptr().cast(), input.len());
        let output = std::slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len());
        avx512::mul_to(
            ShoupFactor::from_raw(factor.value().as_into(), factor.quotient().as_into()),
            input,
            output,
            modulus.as_into(),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (factor, input, output, modulus);
    true
}

#[inline]
pub(super) fn try_add_mul_assign<T: FheUint>(
    factor: ShoupFactor<T>,
    acc: &mut [T],
    rhs: &[T],
    modulus: T,
) -> bool {
    debug_assert_eq!(acc.len(), rhs.len());
    if !available::<T>(acc.len()) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: exact type and CPU features are checked above. The casts preserve
    // lengths and disjoint borrows; full chunks bound each vector load/store.
    unsafe {
        let acc = std::slice::from_raw_parts_mut(acc.as_mut_ptr().cast(), acc.len());
        let rhs = std::slice::from_raw_parts(rhs.as_ptr().cast(), rhs.len());
        avx512::add_mul_assign(
            ShoupFactor::from_raw(factor.value().as_into(), factor.quotient().as_into()),
            acc,
            rhs,
            modulus.as_into(),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (factor, acc, rhs, modulus);
    true
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    use super::ShoupFactor;
    use crate::FactorMul;
    use std::arch::x86_64::*;

    #[inline]
    #[target_feature(enable = "avx512f,avx512dq")]
    fn broadcast(factor: ShoupFactor<u64>, modulus: u64) -> (__m512i, __m512i, __m512i, __m512i) {
        (
            _mm512_set1_epi64(factor.value() as i64),
            _mm512_set1_epi64((factor.quotient() & 0xffff_ffff) as i64),
            _mm512_set1_epi64((factor.quotient() >> 32) as i64),
            _mm512_set1_epi64(modulus as i64),
        )
    }

    // Only the high word of rhs*quotient is needed. Express the four 32-bit
    // partial products as vector operations: the equivalent scalar expression
    // is recognized as a u128 multiply and scalarized by LLVM in this loop.
    #[inline]
    #[target_feature(enable = "avx512f,avx512dq")]
    fn product(
        rhs: __m512i,
        value: __m512i,
        q_lo: __m512i,
        q_hi: __m512i,
        modulus: __m512i,
    ) -> __m512i {
        let mask = _mm512_set1_epi64(0xffff_ffff);
        let rhs_hi = _mm512_srli_epi64::<32>(rhs);
        let p00 = _mm512_mul_epu32(rhs, q_lo);
        let p01 = _mm512_mul_epu32(rhs, q_hi);
        let p10 = _mm512_mul_epu32(rhs_hi, q_lo);
        let p11 = _mm512_mul_epu32(rhs_hi, q_hi);
        // p01 + high(p00), and p10 + low(s1), each fit in u64 even
        // when both operands of the original multiplication are u64::MAX.
        let s1 = _mm512_add_epi64(p01, _mm512_srli_epi64::<32>(p00));
        let s2 = _mm512_add_epi64(p10, _mm512_and_si512(s1, mask));
        let quotient = _mm512_add_epi64(
            p11,
            _mm512_add_epi64(_mm512_srli_epi64::<32>(s1), _mm512_srli_epi64::<32>(s2)),
        );
        let lazy = _mm512_sub_epi64(
            _mm512_mullo_epi64(rhs, value),
            _mm512_mullo_epi64(quotient, modulus),
        );
        _mm512_min_epu64(lazy, _mm512_sub_epi64(lazy, modulus))
    }

    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn mul_assign(factor: ShoupFactor<u64>, values: &mut [u64], modulus: u64) {
        let (value, q_lo, q_hi, q) = broadcast(factor, modulus);
        let (chunks, tail) = values.as_chunks_mut::<8>();
        for chunk in chunks {
            // SAFETY: each chunk contains eight u64s; unaligned access is allowed.
            unsafe {
                let rhs = _mm512_loadu_si512(chunk.as_ptr().cast());
                _mm512_storeu_si512(
                    chunk.as_mut_ptr().cast(),
                    product(rhs, value, q_lo, q_hi, q),
                );
            }
        }
        for out in tail {
            *out = factor.factor_mul_modulo(*out, modulus);
        }
    }

    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn mul_to(
        factor: ShoupFactor<u64>,
        input: &[u64],
        output: &mut [u64],
        modulus: u64,
    ) {
        let (value, q_lo, q_hi, q) = broadcast(factor, modulus);
        let (input, input_tail) = input.as_chunks::<8>();
        let (output, output_tail) = output.as_chunks_mut::<8>();
        for (input, output) in input.iter().zip(output) {
            // SAFETY: both chunks contain eight u64s and borrows are disjoint.
            unsafe {
                let rhs = _mm512_loadu_si512(input.as_ptr().cast());
                _mm512_storeu_si512(
                    output.as_mut_ptr().cast(),
                    product(rhs, value, q_lo, q_hi, q),
                );
            }
        }
        for (&rhs, out) in input_tail.iter().zip(output_tail) {
            *out = factor.factor_mul_modulo(rhs, modulus);
        }
    }

    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn add_mul_assign(
        factor: ShoupFactor<u64>,
        acc: &mut [u64],
        rhs: &[u64],
        modulus: u64,
    ) {
        let (value, q_lo, q_hi, q) = broadcast(factor, modulus);
        let (acc, acc_tail) = acc.as_chunks_mut::<8>();
        let (rhs, rhs_tail) = rhs.as_chunks::<8>();
        for (acc, rhs) in acc.iter_mut().zip(rhs) {
            // SAFETY: both chunks contain eight u64s and borrows are disjoint.
            unsafe {
                let rhs = _mm512_loadu_si512(rhs.as_ptr().cast());
                let acc_value = _mm512_loadu_si512(acc.as_ptr().cast());
                // Normalize before adding: q < 2^63 guarantees acc+product
                // fits in u64, but acc+lazy could overflow for valid moduli.
                let sum = _mm512_add_epi64(acc_value, product(rhs, value, q_lo, q_hi, q));
                _mm512_storeu_si512(
                    acc.as_mut_ptr().cast(),
                    _mm512_min_epu64(sum, _mm512_sub_epi64(sum, q)),
                );
            }
        }
        for (acc, &rhs) in acc_tail.iter_mut().zip(rhs_tail) {
            let sum = *acc + factor.factor_mul_modulo(rhs, modulus);
            *acc = sum.min(sum.wrapping_sub(modulus));
        }
    }
}

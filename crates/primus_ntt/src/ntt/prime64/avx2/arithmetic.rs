//! AVX2 reductions and the Barrett-64 product used by the u64 butterflies.
//!
//! AVX2 has no packed u64 widening multiply. The two product helpers therefore
//! split each lane into 32-bit limbs and compute only the half needed by the
//! Barrett quotient or remainder.

use core::arch::x86_64::*;

/// `x mod bound` for `x < 2*bound` on 4 u64 lanes.
///
/// AVX2 lacks `_mm256_min_epu64`, so we use the unsigned-to-signed compare
/// trick: XOR both operands with the MSB, then use signed `cmpgt`, then
/// blend.
///
/// Equivalent to scalar `x.min(x.wrapping_sub(bound))`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn reduce_once_u64x4(x: __m256i, bound: __m256i) -> __m256i {
    let msb = _mm256_set1_epi64x(i64::MIN);
    // x < bound (unsigned)  ⇔  (x ^ MSB) < (bound ^ MSB) (signed)
    let mask = _mm256_cmpgt_epi64(_mm256_xor_si256(bound, msb), _mm256_xor_si256(x, msb));
    // mask = all 1s where x < bound, all 0s where x >= bound
    // blendv: if mask bit 7 set → take x, else take x - bound
    let sub = _mm256_sub_epi64(x, bound);
    _mm256_blendv_epi8(sub, x, mask)
}

/// `x mod q` for `x < 4*q` on 4 u64 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn reduce_twice_u64x4(x: __m256i, q: __m256i, two_q: __m256i) -> __m256i {
    let x = reduce_once_u64x4(x, two_q); // -> [0, 2q)
    reduce_once_u64x4(x, q) // -> [0, q)
}

/// Returns only the **high** 64 bits of `a * b` (4 lanes).
///
/// The four 32-bit limb products are recombined with the carries entering the
/// high half. Used for the Barrett quotient estimate.
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_hi_u64x4(a: __m256i, b: __m256i) -> __m256i {
    let lo_mask = _mm256_set1_epi64x(0x0000_0000_FFFF_FFFFu64 as i64);
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);
    let z_lo_lo = _mm256_mul_epu32(a, b);
    let z_lo_hi = _mm256_mul_epu32(a, b_hi);
    let z_hi_lo = _mm256_mul_epu32(a_hi, b);
    let z_hi_hi = _mm256_mul_epu32(a_hi, b_hi);

    let z_lo_lo_shift = _mm256_srli_epi64::<32>(z_lo_lo);
    let sum_tmp = _mm256_add_epi64(z_lo_hi, z_lo_lo_shift);
    let sum_lo = _mm256_and_si256(sum_tmp, lo_mask);
    let sum_mid = _mm256_srli_epi64::<32>(sum_tmp);
    let sum_mid2 = _mm256_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm256_srli_epi64::<32>(sum_mid2);
    let sum_hi = _mm256_add_epi64(z_hi_hi, sum_mid);
    _mm256_add_epi64(sum_hi, sum_mid2_hi)
}

/// Returns only the **low** 64 bits of `a * b` (4 lanes).
///
/// The high-high limb product cannot affect this half, so only three
/// `_mm256_mul_epu32` operations are needed.
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_lo_u64x4(a: __m256i, b: __m256i) -> __m256i {
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);
    let z_lo_lo = _mm256_mul_epu32(a, b);
    let z_lo_hi = _mm256_mul_epu32(a, b_hi);
    let z_hi_lo = _mm256_mul_epu32(a_hi, b);
    _mm256_add_epi64(
        _mm256_slli_epi64::<32>(_mm256_add_epi64(z_lo_hi, z_hi_lo)),
        z_lo_lo,
    )
}

/// Barrett-64 lazy multiply for 4 u64 lanes.
///
/// Computes `qhat = hi64(y * wp)` then `t = lo64(y * w) - lo64(q * qhat)`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn mul_mod_lazy_u64x4(y: __m256i, w: __m256i, wp: __m256i, q: __m256i) -> __m256i {
    let qhat = widening_mul_hi_u64x4(y, wp);
    let wy = widening_mul_lo_u64x4(y, w);
    let qq = widening_mul_lo_u64x4(q, qhat);
    _mm256_sub_epi64(wy, qq)
}

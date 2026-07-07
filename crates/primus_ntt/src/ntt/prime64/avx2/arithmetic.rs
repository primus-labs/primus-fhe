use core::arch::x86_64::*;

// Reduction helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 64 × 64 → 128 widening multiply (4 lanes)
// ---------------------------------------------------------------------------

/// Returns `(lo, hi)` where `lo` and `hi` are the low and high 64 bits of
/// the 128-bit products `a * b` for each of the 4 u64 lanes.
///
/// This full reference implementation is not directly called — the callers use
/// `widening_mul_hi_u64x4` and `widening_mul_lo_u64x4` instead, which each
/// save 2–3 instructions by computing only the needed half.
///
/// Algorithm from <https://stackoverflow.com/a/28827013>: each 64-bit
/// operand is split into two 32-bit halves, then 4 cross-products are
/// computed via `_mm256_mul_epu32`.
#[allow(dead_code)]
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_u64x4(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    let lo_mask = _mm256_set1_epi64x(0x0000_0000_FFFF_FFFFu64 as i64);
    // Swap 32-bit halves within each 64-bit lane: [a1, a0] → [a0, a1]
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);

    // 32 × 32 → 64 cross-products
    let z_lo_lo = _mm256_mul_epu32(a, b); // a_lo * b_lo
    let z_lo_hi = _mm256_mul_epu32(a, b_hi); // a_lo * b_hi
    let z_hi_lo = _mm256_mul_epu32(a_hi, b); // a_hi * b_lo
    let z_hi_hi = _mm256_mul_epu32(a_hi, b_hi); // a_hi * b_hi — only needed for full / hi

    // --- low 64 bits ---
    // prod_lo = (z_lo_hi + z_hi_lo) << 32  +  z_lo_lo
    let prod_lo = _mm256_add_epi64(
        _mm256_slli_epi64::<32>(_mm256_add_epi64(z_lo_hi, z_hi_lo)),
        z_lo_lo,
    );

    // --- high 64 bits ---
    let z_lo_lo_shift = _mm256_srli_epi64::<32>(z_lo_lo); // carry from lo
    let sum_tmp = _mm256_add_epi64(z_lo_hi, z_lo_lo_shift);
    let sum_lo = _mm256_and_si256(sum_tmp, lo_mask); // low 32 bits of sum
    let sum_mid = _mm256_srli_epi64::<32>(sum_tmp); // carry to high

    let sum_mid2 = _mm256_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm256_srli_epi64::<32>(sum_mid2); // carry to highest
    let sum_hi = _mm256_add_epi64(z_hi_hi, sum_mid);

    let prod_hi = _mm256_add_epi64(sum_hi, sum_mid2_hi);

    (prod_lo, prod_hi)
}

/// Returns only the **high** 64 bits of `a * b` (4 lanes).
///
/// Saves ~3 instructions vs `widening_mul_u64x4` by skipping the low
/// recombination.  Used by `mul_mod_lazy_u64x4` for the qhat computation.
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
/// Saves 1 `vpmuludq` + ~3 shift/add ops vs `widening_mul_u64x4` by
/// skipping `z_hi_hi` and the full high recombination.
/// Used by `mul_mod_lazy_u64x4` for the two low-half products.
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_lo_u64x4(a: __m256i, b: __m256i) -> __m256i {
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);
    let z_lo_lo = _mm256_mul_epu32(a, b);
    let z_lo_hi = _mm256_mul_epu32(a, b_hi);
    let z_hi_lo = _mm256_mul_epu32(a_hi, b);
    // z_hi_hi is NOT computed — not needed for the low 64 bits.
    _mm256_add_epi64(
        _mm256_slli_epi64::<32>(_mm256_add_epi64(z_lo_hi, z_hi_lo)),
        z_lo_lo,
    )
}

// ---------------------------------------------------------------------------
// Barrett lazy multiply for 64-bit
// ---------------------------------------------------------------------------

/// Barrett-64 lazy multiply for 4 u64 lanes.
///
/// Computes `qhat = hi64(y * wp)` then `t = lo64(y * w) - lo64(q * qhat)`.
/// Uses `widening_mul_hi_u64x4` for the high half and
/// `widening_mul_lo_u64x4` for the two low halves, saving 2 `vpmuludq`
/// per butterfly vs calling the full `widening_mul_u64x4` each time.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn mul_mod_lazy_u64x4(y: __m256i, w: __m256i, wp: __m256i, q: __m256i) -> __m256i {
    let qhat = widening_mul_hi_u64x4(y, wp);
    let wy = widening_mul_lo_u64x4(y, w);
    let qq = widening_mul_lo_u64x4(q, qhat);
    _mm256_sub_epi64(wy, qq)
}

// ---------------------------------------------------------------------------

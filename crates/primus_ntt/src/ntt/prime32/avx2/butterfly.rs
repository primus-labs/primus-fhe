use core::arch::x86_64::*;

use super::arithmetic::{mul_mod_lazy_avx2, reduce_once_avx2};

// Butterflies
// ---------------------------------------------------------------------------

/// Forward Harvey butterfly on 8 u32 lanes.
///
/// Input:  `x`, `y` each in `[0, 4q)`.
/// Output: `x'`, `y'` each in `[0, 4q)`.
///
/// Algorithm:
/// ```text
/// x0 = reduce_once(x, two_q)
/// t  = mul_mod_lazy(y, w, wp, q)
/// x' = x0 + t
/// y' = x0 + two_q - t
/// ```
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn fwd_butterfly_avx2(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let tx = reduce_once_avx2(x, two_q);
    let ty = mul_mod_lazy_avx2(y, w, wp, q);
    let x_new = _mm256_add_epi32(tx, ty);
    let y_new = _mm256_sub_epi32(_mm256_add_epi32(tx, two_q), ty);
    (x_new, y_new)
}

/// Inverse Harvey butterfly on 8 u32 lanes.
///
/// Input:  `x`, `y` each in `[0, 2q)`.
/// Output: `x'`, `y'` each in `[0, 2q)`.
///
/// Algorithm:
/// ```text
/// s  = x + y
/// d  = x + two_q - y
/// x' = reduce_once(s, two_q)
/// y' = mul_mod_lazy(d, w, wp, q)
/// ```
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn inv_butterfly_avx2(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let tx = _mm256_add_epi32(x, y);
    let ty = _mm256_sub_epi32(_mm256_add_epi32(x, two_q), y);
    let x_new = reduce_once_avx2(tx, two_q);
    let y_new = mul_mod_lazy_avx2(ty, w, wp, q);
    (x_new, y_new)
}

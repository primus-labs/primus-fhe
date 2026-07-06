use core::arch::x86_64::*;

use super::arithmetic::{mul_mod_lazy_avx512, reduce_once_avx512};

// Butterflies
// ---------------------------------------------------------------------------

/// Forward Harvey butterfly on 16 u32 lanes.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn fwd_butterfly_avx512(
    x: __m512i,
    y: __m512i,
    w: __m512i,
    wp: __m512i,
    q: __m512i,
    two_q: __m512i,
) -> (__m512i, __m512i) {
    let tx = reduce_once_avx512(x, two_q);
    let ty = mul_mod_lazy_avx512(y, w, wp, q);
    let x_new = _mm512_add_epi32(tx, ty);
    let y_new = _mm512_sub_epi32(_mm512_add_epi32(tx, two_q), ty);
    (x_new, y_new)
}

/// Inverse Harvey butterfly on 16 u32 lanes.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn inv_butterfly_avx512(
    x: __m512i,
    y: __m512i,
    w: __m512i,
    wp: __m512i,
    q: __m512i,
    two_q: __m512i,
) -> (__m512i, __m512i) {
    let tx = _mm512_add_epi32(x, y);
    let ty = _mm512_sub_epi32(_mm512_add_epi32(x, two_q), y);
    let x_new = reduce_once_avx512(tx, two_q);
    let y_new = mul_mod_lazy_avx512(ty, w, wp, q);
    (x_new, y_new)
}

// ---------------------------------------------------------------------------

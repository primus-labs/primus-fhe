use core::arch::x86_64::*;

// Reduction helpers
// ---------------------------------------------------------------------------

/// `x mod q` for `x < 2*q` on 16 u32 lanes.
///
/// Uses `_mm512_min_epu32` — native in AVX-512F, unlike AVX2 where
/// `_mm256_min_epu32` was the widest unsigned min available.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn reduce_once_avx512(x: __m512i, q: __m512i) -> __m512i {
    _mm512_min_epu32(x, _mm512_sub_epi32(x, q))
}

/// `x mod q` for `x < 4*q` on 16 u32 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn reduce_twice_avx512(x: __m512i, q: __m512i, two_q: __m512i) -> __m512i {
    let x = reduce_once_avx512(x, two_q);
    reduce_once_avx512(x, q)
}

// ---------------------------------------------------------------------------

// Barrett-32 lazy multiply for 16 u32 lanes
// ---------------------------------------------------------------------------

/// Barrett-32 lazy multiply for 16 u32 lanes.
///
/// Same even/odd split as the AVX2 version, widened to 512 bits.
///
/// `_mm512_mul_epu32` only multiplies the even-indexed u32 lanes
/// (0,2,4,…,14).  We handle odd lanes (1,3,…,15) by shifting them into
/// the even positions, multiplying, then shifting back.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn mul_mod_lazy_avx512(y: __m512i, w: __m512i, wp: __m512i, q: __m512i) -> __m512i {
    // ---- Step 1: qhat = hi32(y * wp) ----
    //
    // Even lanes (0,2,4,…,14)
    let prod_wp_even = _mm512_mul_epu32(y, wp);
    let qhat_even = _mm512_srli_epi64::<32>(prod_wp_even);

    // Odd lanes (1,3,5,…,15)
    let y_shifted = _mm512_srli_epi64::<32>(y);
    let wp_shifted = _mm512_srli_epi64::<32>(wp);
    let prod_wp_odd = _mm512_mul_epu32(y_shifted, wp_shifted);
    let qhat_odd = _mm512_srli_epi64::<32>(prod_wp_odd);
    let qhat_odd = _mm512_slli_epi64::<32>(qhat_odd);

    // Interleave even/odd into 16 × u32.
    let qhat = _mm512_or_si512(qhat_even, qhat_odd);

    // ---- Step 2: t = low32(w*y) - low32(q*qhat) ----
    let wy = _mm512_mullo_epi32(w, y);
    let q_qhat = _mm512_mullo_epi32(q, qhat);
    _mm512_sub_epi32(wy, q_qhat)
}

// ---------------------------------------------------------------------------

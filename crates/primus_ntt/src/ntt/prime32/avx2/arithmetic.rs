use core::arch::x86_64::*;

// Reduction helpers
// ---------------------------------------------------------------------------

/// `x mod q` for `x < 2*q` on 8 u32 lanes.
///
/// Uses `_mm256_min_epu32` to implement the same branchless unsigned-min
/// pattern as the scalar `x.min(x.wrapping_sub(q))`: when `x < q`,
/// `x - q` wraps to a large unsigned value and `min` picks `x`;
/// when `x >= q`, `min` picks `x - q`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn reduce_once_avx2(x: __m256i, q: __m256i) -> __m256i {
    _mm256_min_epu32(x, _mm256_sub_epi32(x, q))
}

/// `x mod q` for `x < 4*q` on 8 u32 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn reduce_twice_avx2(x: __m256i, q: __m256i, two_q: __m256i) -> __m256i {
    let x = reduce_once_avx2(x, two_q); // -> [0, 2q)
    reduce_once_avx2(x, q) // -> [0, q)
}

// ---------------------------------------------------------------------------

/// Barrett-32 lazy multiply for 8 u32 lanes.
///
/// Computes `qhat = (y * wp) >> 32` then `t = w*y - q*qhat` (all modulo 2³²).
/// Each result is in `[0, 2q)` by the Harvey/Barrett bound (requires `q < 2³⁰`).
///
/// # Implementation note
///
/// AVX2 lacks a full 8-lane `u32 × u32 → u64` multiply. `_mm256_mul_epu32`
/// only multiplies the even-indexed u32 lanes within each 64-bit element.
/// We therefore split the work into even lanes (0, 2, 4, 6) and odd lanes
/// (1, 3, 5, 7), then interleave the results.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn mul_mod_lazy_avx2(y: __m256i, w: __m256i, wp: __m256i, q: __m256i) -> __m256i {
    // ---- Step 1: qhat = hi32(y * wp) ----
    //
    // Even lanes (0,2,4,6) — _mm256_mul_epu32 naturally picks them up.
    let prod_wp_even = _mm256_mul_epu32(y, wp);
    // After srli_epi64::<32>, each 64-bit lane's high 32 bits are already
    // zero — no mask needed.
    let qhat_even = _mm256_srli_epi64::<32>(prod_wp_even);

    // Odd lanes (1,3,5,7): shift both y and wp so their odd-positioned
    // values move to the even positions that _mm256_mul_epu32 reads from.
    let y_shifted = _mm256_srli_epi64::<32>(y);
    let wp_shifted = _mm256_srli_epi64::<32>(wp);
    let prod_wp_odd = _mm256_mul_epu32(y_shifted, wp_shifted);
    let qhat_odd = _mm256_srli_epi64::<32>(prod_wp_odd);
    // Move the odd qhat values to the upper 32 bits of each 64-bit lane,
    // where the odd u32 lanes live in the 256-bit register.
    let qhat_odd = _mm256_slli_epi64::<32>(qhat_odd);

    // Interleave even and odd qhat into one vector of 8 × u32.
    let qhat = _mm256_or_si256(qhat_even, qhat_odd);

    // ---- Step 2: t = low32(w*y) - low32(q*qhat) ----
    let wy = _mm256_mullo_epi32(w, y);
    let q_qhat = _mm256_mullo_epi32(q, qhat);
    _mm256_sub_epi32(wy, q_qhat)
}

// ---------------------------------------------------------------------------

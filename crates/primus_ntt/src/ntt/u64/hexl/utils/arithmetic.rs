use core::arch::x86_64::*;

use super::CmpInt;

/// Returns lower NumBits bits from a 64-bit value
#[target_feature(enable = "avx512f")]
#[inline]
pub fn clear_top_bits_64<const NUM_BITS: u32>(x: __m512i) -> __m512i {
    let low52b_mask = _mm512_set1_epi64(((1u64 << NUM_BITS) - 1) as i64);
    _mm512_and_epi64(x, low52b_mask)
}

/// Multiplies packed unsigned 64-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 128-bit result.
///
/// Returns the high 64-bit unsigned integer from the intermediate result.
#[target_feature(enable = "avx512f")]
#[inline]
pub fn _mm512_hexl_mulhi_epi_64(x: __m512i, y: __m512i) -> __m512i {
    // https://stackoverflow.com/questions/28807341/simd-signed-with-unsigned-multiplication-for-64-bit-64-bit-to-128-bit
    let lo_mask = _mm512_set1_epi64(0x0000_0000_FFFF_FFFFi64);
    // Shuffle high bits with low bits in each 64-bit integer =>
    // x0_lo, x0_hi, x1_lo, x1_hi, x2_lo, x2_hi, ...
    let x_hi = _mm512_shuffle_epi32::<0xB1>(x);
    // y0_lo, y0_hi, y1_lo, y1_hi, y2_lo, y2_hi, ...
    let y_hi = _mm512_shuffle_epi32::<0xB1>(y);
    let z_lo_lo = _mm512_mul_epu32(x, y); // x_lo * y_lo
    let z_lo_hi = _mm512_mul_epu32(x, y_hi); // x_lo * y_hi
    let z_hi_lo = _mm512_mul_epu32(x_hi, y); // x_hi * y_lo
    let z_hi_hi = _mm512_mul_epu32(x_hi, y_hi); // x_hi * y_hi

    //                   x_hi | x_lo
    // x                 y_hi | y_lo
    // ------------------------------
    //                  [x_lo * y_lo]    // z_lo_lo
    // +           [z_lo * y_hi]         // z_lo_hi
    // +           [x_hi * y_lo]         // z_hi_lo
    // +    [x_hi * y_hi]                // z_hi_hi
    //     ^-----------^ <-- only bits needed
    //  sum_|  hi | mid | lo  |

    // Low bits of z_lo_lo are not needed
    let z_lo_lo_shift = _mm512_srli_epi64::<32>(z_lo_lo);

    //                   [x_lo  *  y_lo] // z_lo_lo
    //          + [z_lo  *  y_hi]        // z_lo_hi
    //          ------------------------
    //            |    sum_tmp   |
    //            |sum_mid|sum_lo|
    let sum_tmp = _mm512_add_epi64(z_lo_hi, z_lo_lo_shift);
    let sum_lo = _mm512_and_si512(sum_tmp, lo_mask);
    let sum_mid = _mm512_srli_epi64::<32>(sum_tmp);
    //            |       |sum_lo|
    //          + [x_hi   *  y_lo]       // z_hi_lo
    //          ------------------
    //            [   sum_mid2   ]
    let sum_mid2 = _mm512_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm512_srli_epi64::<32>(sum_mid2);
    let sum_hi = _mm512_add_epi64(z_hi_hi, sum_mid);
    _mm512_add_epi64(sum_hi, sum_mid2_hi)
}

/// Multiplies packed unsigned 52-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 104-bit result.
///
/// Returns the high 52-bit unsigned integer from the intermediate result.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn _mm512_hexl_mulhi_epi_52(x: __m512i, y: __m512i) -> __m512i {
    // let zero = _mm512_set1_epi64(0);
    let zero = _mm512_setzero_si512();
    _mm512_madd52hi_epu64(zero, x, y)
}

/// Multiplies packed unsigned 64-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 128-bit result.
///
/// Returns the high 64-bit unsigned integer from the intermediate result,
/// with approximation error at most 1.
#[target_feature(enable = "avx512f")]
#[inline]
pub fn _mm512_hexl_mulhi_approx_epi_64(x: __m512i, y: __m512i) -> __m512i {
    // https://stackoverflow.com/questions/28807341/simd-signed-with-unsigned-multiplication-for-64-bit-64-bit-to-128-bit
    let lo_mask = _mm512_set1_epi64(0x0000_0000_FFFF_FFFFi64);
    // Shuffle high bits with low bits in each 64-bit integer =>
    // x0_lo, x0_hi, x1_lo, x1_hi, x2_lo, x2_hi, ...
    let x_hi = _mm512_shuffle_epi32::<0xB1>(x);
    // y0_lo, y0_hi, y1_lo, y1_hi, y2_lo, y2_hi, ...
    let y_hi = _mm512_shuffle_epi32::<0xB1>(y);
    let z_lo_hi = _mm512_mul_epu32(x, y_hi); // x_lo * y_hi
    let z_hi_lo = _mm512_mul_epu32(x_hi, y); // x_hi * y_lo
    let z_hi_hi = _mm512_mul_epu32(x_hi, y_hi); // x_hi * y_hi

    //                   x_hi | x_lo
    // x                 y_hi | y_lo
    // ------------------------------
    //                  [x_lo * y_lo]    // unused, resulting in approximation
    // +           [z_lo * y_hi]         // z_lo_hi
    // +           [x_hi * y_lo]         // z_hi_lo
    // +    [x_hi * y_hi]                // z_hi_hi
    //     ^-----------^ <-- only bits needed
    //  sum_|  hi | mid | lo  |

    let sum_lo = _mm512_and_si512(z_lo_hi, lo_mask);
    let sum_mid = _mm512_srli_epi64::<32>(z_lo_hi);
    //            |       |sum_lo|
    //          + [x_hi   *  y_lo]       // z_hi_lo
    //          ------------------
    //            [   sum_mid2   ]
    let sum_mid2 = _mm512_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm512_srli_epi64::<32>(sum_mid2);
    let sum_hi = _mm512_add_epi64(z_hi_hi, sum_mid);
    _mm512_add_epi64(sum_hi, sum_mid2_hi)
}

/// Multiplies packed unsigned 52-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 104-bit result.
///
/// Returns the high 52-bit unsigned integer from the intermediate result,
/// with approximation error at most 1.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn _mm512_hexl_mulhi_approx_epi_52(x: __m512i, y: __m512i) -> __m512i {
    // let zero = _mm512_set1_epi64(0);
    let zero = _mm512_setzero_si512();
    _mm512_madd52hi_epu64(zero, x, y)
}

/// Multiplies packed unsigned 64-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 128-bit result.
///
/// Returns the low 64-bit unsigned integer from the intermediate result.
#[target_feature(enable = "avx512dq")]
#[inline]
pub fn _mm512_hexl_mullo_epi_64(x: __m512i, y: __m512i) -> __m512i {
    _mm512_mullo_epi64(x, y)
}

/// Multiplies packed unsigned 52-bit integers in each 64-bit lane of `x` and `y`,
/// producing an intermediate 104-bit result.
///
/// Returns the low 52-bit unsigned integer from the intermediate result.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn _mm512_hexl_mullo_epi_52(x: __m512i, y: __m512i) -> __m512i {
    // let zero = _mm512_set1_epi64(0);
    let zero = _mm512_setzero_si512();
    _mm512_madd52lo_epu64(zero, x, y)
}

/// Multiplies packed unsigned 52-bit integers in each 64-bit lane of `y` and `z`,
/// producing an intermediate 104-bit result.
///
/// The low 52 bits of the product are added to `x`, and then the low 52
/// bits are returned.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub fn _mm512_hexl_mullo_add_lo_epi_52(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    let result = _mm512_madd52lo_epu64(x, y, z);

    // Clear high 12 bits from result
    clear_top_bits_64::<52>(result)
}

/// Multiplies packed unsigned 64-bit integers in each 64-bit lane of `y` and `z`,
/// producing an intermediate 128-bit result.
///
/// The low 64 bits of the product are added to `x`, and then the low 64
/// bits are returned.
#[target_feature(enable = "avx512f,avx512dq")]
#[inline]
pub fn _mm512_hexl_mullo_add_lo_epi_64(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    let prod = _mm512_mullo_epi64(y, z);
    _mm512_add_epi64(x, prod)
}

/// Returns `x mod q` in each 64-bit SIMD lane.
///
/// Assumes `x < 2 * q` in all lanes.
#[target_feature(enable = "avx512f")]
#[inline]
pub fn _mm512_hexl_small_mod_epu64_2(x: __m512i, q: __m512i) -> __m512i {
    _mm512_min_epu64(x, _mm512_sub_epi64(x, q))
}

/// Returns `(x + y) mod q`; assumes `0 < x, y < q`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn _mm512_hexl_small_add_mod_epi64(x: __m512i, y: __m512i, q: __m512i) -> __m512i {
    _mm512_hexl_small_mod_epu64_2(_mm512_add_epi64(x, y), q)
}

/// Returns `(x - y) mod q`; assumes `0 < x, y < q`
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_small_sub_mod_epi64(x: __m512i, y: __m512i, q: __m512i) -> __m512i {
    // diff = x - y
    // return (diff < 0) ? (diff + q) : diff
    let v_diff = _mm512_sub_epi64(x, y);
    let sign_bits: __mmask8 = _mm512_movepi64_mask(v_diff);
    _mm512_mask_add_epi64(v_diff, sign_bits, v_diff, q)
}

/// Compares packed unsigned 64-bit integers in `a` and `b` and returns an AVX-512 mask.
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_cmp_epu64_mask(a: __m512i, b: __m512i, cmp: CmpInt) -> __mmask8 {
    match cmp {
        CmpInt::Eq => _mm512_cmp_epu64_mask::<{ CmpInt::Eq as i32 }>(a, b),
        CmpInt::Lt => _mm512_cmp_epu64_mask::<{ CmpInt::Lt as i32 }>(a, b),
        CmpInt::Le => _mm512_cmp_epu64_mask::<{ CmpInt::Le as i32 }>(a, b),
        CmpInt::False => _mm512_cmp_epu64_mask::<{ CmpInt::False as i32 }>(a, b),
        CmpInt::Ne => _mm512_cmp_epu64_mask::<{ CmpInt::Ne as i32 }>(a, b),
        CmpInt::Nlt => _mm512_cmp_epu64_mask::<{ CmpInt::Nlt as i32 }>(a, b),
        CmpInt::Nle => _mm512_cmp_epu64_mask::<{ CmpInt::Nle as i32 }>(a, b),
        CmpInt::True => _mm512_cmp_epu64_mask::<{ CmpInt::True as i32 }>(a, b),
    }
}

/// Returns `c[i] = (a[i] CMP b[i]) ? match_value : 0` (per 64-bit lane, unsigned compare).
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_cmp_epi64(a: __m512i, b: __m512i, cmp: CmpInt, match_value: u64) -> __m512i {
    let mask: __mmask8 = _mm512_hexl_cmp_epu64_mask(a, b, cmp);
    let v = _mm_set1_epi64x(match_value as i64);

    // Broadcast `v` to 512-bit and zero lanes where mask bit is 0.
    _mm512_maskz_broadcastq_epi64(mask, v)
}

/// Returns `c[i] = (a[i] >= b[i]) ? match_value : 0` (per 64-bit lane, unsigned compare).
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_cmpge_epu64(a: __m512i, b: __m512i, match_value: u64) -> __m512i {
    _mm512_hexl_cmp_epi64(a, b, CmpInt::Nlt, match_value)
}

/// Returns `c[i] = (a[i] < b[i]) ? match_value : 0` (per 64-bit lane, unsigned compare).
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_cmplt_epu64(a: __m512i, b: __m512i, match_value: u64) -> __m512i {
    _mm512_hexl_cmp_epi64(a, b, CmpInt::Lt, match_value)
}

/// Returns `c[i] = (a[i] <= b[i]) ? match_value : 0` (per 64-bit lane, unsigned compare).
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
pub fn _mm512_hexl_cmple_epu64(a: __m512i, b: __m512i, match_value: u64) -> __m512i {
    _mm512_hexl_cmp_epi64(a, b, CmpInt::Le, match_value)
}

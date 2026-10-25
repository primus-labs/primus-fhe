//! Lane deinterleaving for the four packed AVX-512 stages.
//!
//! Each helper turns 32 consecutive coefficients into one vector of butterfly
//! left operands and one vector of right operands. The paired store reverses
//! exactly that permutation. Keeping arithmetic out of this module makes the
//! lane layout independently checkable against the precomputed twiddle order.
//!
//! All layouts below are written from low address / SIMD lane 0 to high address
//! / lane 15. Each input block contains one or more radix-2 groups laid out as
//! consecutive `x` coefficients followed by their corresponding `y`
//! coefficients.

use core::arch::x86_64::*;

/// Loads two T8 groups and separates their x/y halves.
///
/// ```text
/// memory = [x0..x7 | y0..y7 | x8..x15 | y8..y15]
/// a      = [x0..x7 | y0..y7]
/// b      = [x8..x15 | y8..y15]
/// x      = [x0..x15]
/// y      = [y0..y15]
/// ```
///
/// `0x44` selects the low two 128-bit lanes from both `a` and `b`; `0xEE`
/// selects the high two. Consequently the twiddle vector contains eight
/// copies of each T8 root.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t8_load_xy(block: &[u32; 32]) -> (__m512i, __m512i) {
    let ptr = block.as_ptr().cast::<__m512i>();
    let a = unsafe { _mm512_loadu_si512(ptr) };
    let b = unsafe { _mm512_loadu_si512(ptr.add(1)) };
    (
        _mm512_shuffle_i32x4::<0x44>(a, b),
        _mm512_shuffle_i32x4::<0xEE>(a, b),
    )
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t8_store_xy(x: __m512i, y: __m512i, block: &mut [u32; 32]) {
    // The same lane selections reverse the load: low x/y halves form the first
    // T8 group and high x/y halves form the second.
    let ptr = block.as_mut_ptr().cast::<__m512i>();
    unsafe {
        _mm512_storeu_si512(ptr, _mm512_shuffle_i32x4::<0x44>(x, y));
        _mm512_storeu_si512(ptr.add(1), _mm512_shuffle_i32x4::<0xEE>(x, y));
    }
}

/// Loads four T4 groups and collects their alternating 128-bit x/y lanes.
///
/// ```text
/// memory = [x0..x3 | y0..y3 | x4..x7 | y4..y7 |
///           x8..x11 | y8..y11 | x12..x15 | y12..y15]
/// a      = [x0..x3 | y0..y3 | x4..x7 | y4..y7]
/// b      = [x8..x11 | y8..y11 | x12..x15 | y12..y15]
/// x      = [x0..x15]
/// y      = [y0..y15]
/// ```
///
/// `0x88` selects even 128-bit lanes from `a` and `b`; `0xDD` selects odd
/// lanes. Each four-lane run therefore uses one T4 root.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t4_load_xy(block: &[u32; 32]) -> (__m512i, __m512i) {
    let ptr = block.as_ptr().cast::<__m512i>();
    let a = unsafe { _mm512_loadu_si512(ptr) };
    let b = unsafe { _mm512_loadu_si512(ptr.add(1)) };
    (
        _mm512_shuffle_i32x4::<0x88>(a, b),
        _mm512_shuffle_i32x4::<0xDD>(a, b),
    )
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t4_store_xy(x: __m512i, y: __m512i, block: &mut [u32; 32]) {
    // First regroup [xA,xC,yA,yC] / [xB,xD,yB,yD], then restore the
    // consecutive [xA,yA,xB,yB] / [xC,yC,xD,yD] block layout.
    let ac = _mm512_shuffle_i32x4::<0x88>(x, y);
    let bd = _mm512_shuffle_i32x4::<0xDD>(x, y);
    let ptr = block.as_mut_ptr().cast::<__m512i>();
    unsafe {
        _mm512_storeu_si512(ptr, _mm512_shuffle_i32x4::<0x88>(ac, bd));
        _mm512_storeu_si512(ptr.add(1), _mm512_shuffle_i32x4::<0xDD>(ac, bd));
    }
}

/// Loads eight T2 groups and separates their 64-bit x/y halves.
///
/// ```text
/// memory = [x0,x1,y0,y1 | x2,x3,y2,y3 | ... | x14,x15,y14,y15]
/// x      = [x0,x1,x8,x9 | x2,x3,x10,x11 |
///           x4,x5,x12,x13 | x6,x7,x14,x15]
/// y      = [y0,y1,y8,y9 | y2,y3,y10,y11 |
///           y4,y5,y12,y13 | y6,y7,y14,y15]
/// ```
///
/// Each 128-bit lane contains one T2 group. `unpacklo_epi64` takes its x half
/// and pairs corresponding groups from the two loads; `unpackhi_epi64` does
/// the same for y. This is why T2 roots use block order `0,4,1,5,2,6,3,7`,
/// with every root repeated twice.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t2_load_xy(block: &[u32; 32]) -> (__m512i, __m512i) {
    let ptr = block.as_ptr().cast::<__m512i>();
    let a = unsafe { _mm512_loadu_si512(ptr) };
    let b = unsafe { _mm512_loadu_si512(ptr.add(1)) };
    (_mm512_unpacklo_epi64(a, b), _mm512_unpackhi_epi64(a, b))
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t2_store_xy(x: __m512i, y: __m512i, block: &mut [u32; 32]) {
    // Pairing the low and high 64-bit halves again restores the eight
    // `[x0,x1,y0,y1]`-style T2 groups.
    let ptr = block.as_mut_ptr().cast::<__m512i>();
    unsafe {
        _mm512_storeu_si512(ptr, _mm512_unpacklo_epi64(x, y));
        _mm512_storeu_si512(ptr.add(1), _mm512_unpackhi_epi64(x, y));
    }
}

/// Loads sixteen adjacent T1 `[x, y]` pairs into separate vectors.
///
/// ```text
/// memory = [x0,y0,x1,y1, ... ,x15,y15]
/// x      = [x0,x1,x8,x9 | x2,x3,x10,x11 |
///           x4,x5,x12,x13 | x6,x7,x14,x15]
/// y      = [y0,y1,y8,y9 | y2,y3,y10,y11 |
///           y4,y5,y12,y13 | y6,y7,y14,y15]
/// ```
///
/// First `0xD8` changes each 128-bit lane from
/// `[x0,y0,x1,y1]` to `[x0,x1,y0,y1]`. The 64-bit unpacks then combine the
/// corresponding halves of the first eight and last eight pairs. The T1 root
/// vector follows the resulting order `0,1,8,9,2,3,10,11,4,5,12,13,6,7,14,15`.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t1_load_xy(block: &[u32; 32]) -> (__m512i, __m512i) {
    let ptr = block.as_ptr().cast::<__m512i>();
    let a = unsafe { _mm512_loadu_si512(ptr) };
    let b = unsafe { _mm512_loadu_si512(ptr.add(1)) };

    // Within each 128-bit lane: [x0,y0,x1,y1] -> [x0,x1,y0,y1].
    let a = _mm512_shuffle_epi32::<0xD8>(a);
    let b = _mm512_shuffle_epi32::<0xD8>(b);
    (_mm512_unpacklo_epi64(a, b), _mm512_unpackhi_epi64(a, b))
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn t1_store_xy(x: __m512i, y: __m512i, block: &mut [u32; 32]) {
    // Unpack recreates `[x0,x1,y0,y1]`; `0xD8` is its own inverse for this
    // arrangement and restores adjacent `[x,y]` pairs.
    let a = _mm512_shuffle_epi32::<0xD8>(_mm512_unpacklo_epi64(x, y));
    let b = _mm512_shuffle_epi32::<0xD8>(_mm512_unpackhi_epi64(x, y));
    let ptr = block.as_mut_ptr().cast::<__m512i>();
    unsafe {
        _mm512_storeu_si512(ptr, a);
        _mm512_storeu_si512(ptr.add(1), b);
    }
}

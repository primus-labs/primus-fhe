use core::arch::x86_64::*;

use super::arithmetic::reduce_twice_avx512;
use super::butterfly::{fwd_butterfly_avx512, inv_butterfly_avx512};

// T4 store masks
// ---------------------------------------------------------------------------
// T4 load uses `_mm512_shuffle_i32x4`; store still needs 128-bit x/y interleaving.

#[rustfmt::skip]
const PERM_T4_STORE_A: [i32; 16] = [
    0,  1,  2,  3,    // xA0..xA3 <- v_x  0..3
    16, 17, 18, 19,   // yA0..yA3 <- v_y  0..3
    4,  5,  6,  7,    // xB0..xB3 <- v_x  4..7
    20, 21, 22, 23,   // yB0..yB3 <- v_y  4..7
];

#[rustfmt::skip]
const PERM_T4_STORE_B: [i32; 16] = [
    8,  9,  10, 11,   // xC0..xC3 <- v_x  8..11
    24, 25, 26, 27,   // yC0..yC3 <- v_y  8..11
    12, 13, 14, 15,   // xD0..xD3 <- v_x 12..15
    28, 29, 30, 31,   // yD0..yD3 <- v_y 12..15
];

// ---------------------------------------------------------------------------
// T4 store helper masks
// ---------------------------------------------------------------------------

/// Pre-loaded T4 store permutation masks.
pub(super) struct DeinterleaveMasks {
    idx_sa: __m512i,
    idx_sb: __m512i,
}

impl DeinterleaveMasks {
    #[target_feature(enable = "avx512f")]
    unsafe fn load(sa: &[i32; 16], sb: &[i32; 16]) -> Self {
        unsafe {
            Self {
                idx_sa: _mm512_loadu_si512(sa.as_ptr().cast()),
                idx_sb: _mm512_loadu_si512(sb.as_ptr().cast()),
            }
        }
    }

    pub(super) fn for_t4() -> Self {
        unsafe { Self::load(&PERM_T4_STORE_A, &PERM_T4_STORE_B) }
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_t8(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x44>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xEE>(v_a, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_shuffle_i32x4::<0x44>(v_x, v_y);
        let b_out = _mm512_shuffle_i32x4::<0xEE>(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_t8(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x44>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xEE>(v_a, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_shuffle_i32x4::<0x44>(v_x, v_y);
        let b_out = _mm512_shuffle_i32x4::<0xEE>(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_t4(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
    masks: &DeinterleaveMasks,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x88>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xDD>(v_a, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_permutex2var_epi32(v_x, masks.idx_sa, v_y);
        let b_out = _mm512_permutex2var_epi32(v_x, masks.idx_sb, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_t4(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
    masks: &DeinterleaveMasks,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x88>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xDD>(v_a, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_permutex2var_epi32(v_x, masks.idx_sa, v_y);
        let b_out = _mm512_permutex2var_epi32(v_x, masks.idx_sb, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_t2(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_unpacklo_epi64(v_a, v_b);
        let v_y = _mm512_unpackhi_epi64(v_a, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_unpacklo_epi64(v_x, v_y);
        let b_out = _mm512_unpackhi_epi64(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_t2(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_unpacklo_epi64(v_a, v_b);
        let v_y = _mm512_unpackhi_epi64(v_a, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_unpacklo_epi64(v_x, v_y);
        let b_out = _mm512_unpackhi_epi64(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_t1<const REDUCE: bool>(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let s_a = _mm512_shuffle_epi32::<0xD8>(v_a);
        let s_b = _mm512_shuffle_epi32::<0xD8>(v_b);
        let v_x = _mm512_unpacklo_epi64(s_a, s_b);
        let v_y = _mm512_unpackhi_epi64(s_a, s_b);

        let (mut v_x, mut v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
        if REDUCE {
            v_x = reduce_twice_avx512(v_x, v_q, v_two_q);
            v_y = reduce_twice_avx512(v_y, v_q, v_two_q);
        }

        let s_a = _mm512_unpacklo_epi64(v_x, v_y);
        let s_b = _mm512_unpackhi_epi64(v_x, v_y);
        let a_out = _mm512_shuffle_epi32::<0xD8>(s_a);
        let b_out = _mm512_shuffle_epi32::<0xD8>(s_b);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_t1(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let s_a = _mm512_shuffle_epi32::<0xD8>(v_a);
        let s_b = _mm512_shuffle_epi32::<0xD8>(v_b);
        let v_x = _mm512_unpacklo_epi64(s_a, s_b);
        let v_y = _mm512_unpackhi_epi64(s_a, s_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let s_a = _mm512_unpacklo_epi64(v_x, v_y);
        let s_b = _mm512_unpackhi_epi64(v_x, v_y);
        let a_out = _mm512_shuffle_epi32::<0xD8>(s_a);
        let b_out = _mm512_shuffle_epi32::<0xD8>(s_b);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

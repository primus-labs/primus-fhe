use core::arch::x86_64::*;

use super::arithmetic::reduce_twice_avx512;
use super::butterfly::{fwd_butterfly_avx512, inv_butterfly_avx512};

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
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x88>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xDD>(v_a, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        // 2-stage 128-bit reinterleave via shuffle_i32x4 (lower latency than
        // permutex2var with mask loads; no register pressure from mask vectors).
        // Stage 1: regroup — [xA,xC,yA,yC] and [xB,xD,yB,yD].
        let t1 = _mm512_shuffle_i32x4::<0x88>(v_x, v_y);
        let t2 = _mm512_shuffle_i32x4::<0xDD>(v_x, v_y);
        // Stage 2: interleave into block pairs — [xA,yA,xB,yB] and [xC,yC,xD,yD].
        let a_out = _mm512_shuffle_i32x4::<0x88>(t1, t2);
        let b_out = _mm512_shuffle_i32x4::<0xDD>(t1, t2);
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
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x88>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xDD>(v_a, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        // 2-stage 128-bit reinterleave via shuffle_i32x4 (lower latency than
        // permutex2var with mask loads; no register pressure from mask vectors).
        // Stage 1: regroup — [xA,xC,yA,yC] and [xB,xD,yB,yD].
        let t1 = _mm512_shuffle_i32x4::<0x88>(v_x, v_y);
        let t2 = _mm512_shuffle_i32x4::<0xDD>(v_x, v_y);
        // Stage 2: interleave into block pairs — [xA,yA,xB,yB] and [xC,yC,xD,yD].
        let a_out = _mm512_shuffle_i32x4::<0x88>(t1, t2);
        let b_out = _mm512_shuffle_i32x4::<0xDD>(t1, t2);
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

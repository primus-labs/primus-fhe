use core::arch::x86_64::*;

/// Given input lanes: `0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15`,
/// returns:
///
/// - `out1 = _mm512_set_epi64(14, 6, 12, 4, 10, 2, 8, 0)`
/// - `out2 = _mm512_set_epi64(15, 7, 13, 5, 11, 3, 9, 1)`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_fwd_interleaved_t1(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let arg_512: *const __m512i = arg.as_ptr().cast();

    // 0, 1, 2, 3, 4, 5, 6, 7
    let v1 = unsafe { _mm512_loadu_si512(arg_512) };
    // 8, 9, 10, 11, 12, 13, 14, 15
    let v2 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };

    let perm_idx = _mm512_set_epi64(6, 7, 4, 5, 2, 3, 0, 1);

    // 1, 0, 3, 2, 5, 4, 7, 6
    let v1_perm = _mm512_permutexvar_epi64(perm_idx, v1);
    // 9, 8, 11, 10, 13, 12, 15, 14
    let v2_perm = _mm512_permutexvar_epi64(perm_idx, v2);

    (
        _mm512_mask_blend_epi64(0xaa_u8, v1, v2_perm),
        _mm512_mask_blend_epi64(0xaa_u8, v1_perm, v2),
    )
}

/// Given input: `0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15`,
/// returns:
/// - `out1 =  _mm512_set_epi64(14, 12, 10, 8, 6, 4, 2, 0)`
/// - `out2 =  _mm512_set_epi64(15, 13, 11, 9, 7, 5, 3, 1)`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_inv_interleaved_t1(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let vperm_hi_idx = _mm512_set_epi64(6, 4, 2, 0, 7, 5, 3, 1);
    let vperm_lo_idx = _mm512_set_epi64(7, 5, 3, 1, 6, 4, 2, 0);
    let vperm2_idx = _mm512_set_epi64(3, 2, 1, 0, 7, 6, 5, 4);

    let arg_512: *const __m512i = arg.as_ptr().cast();

    // 7, 6, 5, 4, 3, 2, 1, 0
    let v_7to0 = unsafe { _mm512_loadu_si512(arg_512) };
    // 15, 14, 13, 12, 11, 10, 9, 8
    let v_15to8 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };
    // 7, 5, 3, 1, 6, 4, 2, 0
    let perm_lo = _mm512_permutexvar_epi64(vperm_lo_idx, v_7to0);
    // 14, 12, 10, 8, 15, 13, 11, 9
    let perm_hi = _mm512_permutexvar_epi64(vperm_hi_idx, v_15to8);

    let out1 = _mm512_mask_blend_epi64(0x0f_u8, perm_hi, perm_lo);
    let out2 = _mm512_mask_blend_epi64(0xf0_u8, perm_hi, perm_lo);
    (out1, _mm512_permutexvar_epi64(vperm2_idx, out2))
}

/// Given input: `0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15`,
/// returns:
/// - `out1 =  _mm512_set_epi64(13, 12, 9, 8, 5, 4, 1, 0)`
/// - `out2 =  _mm512_set_epi64(15, 14, 11, 10, 7, 6, 3, 2)`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_fwd_interleaved_t2(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let arg_512: *const __m512i = arg.as_ptr().cast();

    // 11, 10, 9, 8, 3, 2, 1, 0
    let v1 = unsafe { _mm512_loadu_si512(arg_512) };
    // 15, 14, 13, 12, 7, 6, 5, 4
    let v2 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };

    let v1_perm_idx = _mm512_set_epi64(5, 4, 7, 6, 1, 0, 3, 2);

    let v1_perm = _mm512_permutexvar_epi64(v1_perm_idx, v1);
    let v2_perm = _mm512_permutexvar_epi64(v1_perm_idx, v2);

    (
        _mm512_mask_blend_epi64(0xcc_u8, v1, v2_perm),
        _mm512_mask_blend_epi64(0xcc_u8, v1_perm, v2),
    )
}

/// Given input: `0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15`
/// returns:
/// - `out1 =  _mm512_set_epi64(14, 12, 10, 8, 6, 4, 2, 0)`
/// - `out2 =  _mm512_set_epi64(15, 13, 11, 9, 7, 5, 3, 1)`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_inv_interleaved_t2(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let arg_512: *const __m512i = arg.as_ptr().cast();

    let v1 = unsafe { _mm512_loadu_si512(arg_512) };
    let v2 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };

    let v1_perm_idx = _mm512_set_epi64(6, 7, 4, 5, 2, 3, 0, 1);

    let v1_perm = _mm512_permutexvar_epi64(v1_perm_idx, v1);
    let v2_perm = _mm512_permutexvar_epi64(v1_perm_idx, v2);

    (
        _mm512_mask_blend_epi64(0xaa_u8, v1, v2_perm),
        _mm512_mask_blend_epi64(0xaa_u8, v1_perm, v2),
    )
}

/// Returns:
/// - `out1 =  _mm512_set_epi64(arg[11], arg[10], arg[9], arg[8], arg[3], arg[2], arg[1], arg[0])`
/// - `out2 =  _mm512_set_epi64(arg[15], arg[14], arg[13], arg[12], arg[7], arg[6], arg[5], arg[4])`
#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_fwd_interleaved_t4(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let arg_512: *const __m512i = arg.as_ptr().cast();

    let vperm2_idx = _mm512_set_epi64(3, 2, 1, 0, 7, 6, 5, 4);
    let v_7to0 = unsafe { _mm512_loadu_si512(arg_512) };
    let v_15to8 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };
    let perm_hi = _mm512_permutexvar_epi64(vperm2_idx, v_15to8);
    let out1 = _mm512_mask_blend_epi64(0x0f_u8, perm_hi, v_7to0);
    let mut out2 = _mm512_mask_blend_epi64(0xf0_u8, perm_hi, v_7to0);
    out2 = _mm512_permutexvar_epi64(vperm2_idx, out2);
    (out1, out2)
}

#[target_feature(enable = "avx512f")]
#[inline]
pub fn load_inv_interleaved_t4(arg: &[u64; 16]) -> (__m512i, __m512i) {
    let arg_512: *const __m512i = arg.as_ptr().cast();

    // 0, 1, 2, 3, 4, 5, 6, 7
    let v1 = unsafe { _mm512_loadu_si512(arg_512) };
    // 8, 9, 10, 11, 12, 13, 14, 15
    let v2 = unsafe { _mm512_loadu_si512(arg_512.add(1)) };
    let perm_idx = _mm512_set_epi64(5, 4, 7, 6, 1, 0, 3, 2);

    // 1, 0, 3, 2, 5, 4, 7, 6
    let v1_perm = _mm512_permutexvar_epi64(perm_idx, v1);
    // 9, 8, 11, 10, 13, 12, 15, 14
    let v2_perm = _mm512_permutexvar_epi64(perm_idx, v2);

    (
        _mm512_mask_blend_epi64(0xcc_u8, v1, v2_perm),
        _mm512_mask_blend_epi64(0xcc_u8, v1_perm, v2),
    )
}

/// Given inputs:
/// - `arg1 = _mm512_set_epi64(15, 14, 13, 12, 11, 10, 9, 8)`
/// - `arg2 = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0)`
///
/// Writes `out = {8, 0, 9, 1, 10, 2, 11, 3, 12, 4, 13, 5, 14, 6, 15, 7}`.
#[target_feature(enable = "avx512f")]
#[inline]
pub fn write_fwd_interleaved_t1(mut arg1: __m512i, mut arg2: __m512i, out: &mut [u64; 16]) {
    let vperm2_idx = _mm512_set_epi64(3, 2, 1, 0, 7, 6, 5, 4);
    let v_x_out_idx = _mm512_set_epi64(7, 3, 6, 2, 5, 1, 4, 0);
    let v_y_out_idx = _mm512_set_epi64(3, 7, 2, 6, 1, 5, 0, 4);

    // v_Y => (4, 5, 6, 7, 0, 1, 2, 3)
    arg2 = _mm512_permutexvar_epi64(vperm2_idx, arg2);
    // 4, 5, 6, 7, 12, 13, 14, 15
    let perm_lo = _mm512_mask_blend_epi64(0x0f_u8, arg1, arg2);

    // 8, 9, 10, 11, 0, 1, 2, 3
    let perm_hi = _mm512_mask_blend_epi64(0xf0_u8, arg1, arg2);

    arg1 = _mm512_permutexvar_epi64(v_x_out_idx, perm_hi);
    arg2 = _mm512_permutexvar_epi64(v_y_out_idx, perm_lo);

    let pt: *mut __m512i = out.as_mut_ptr().cast();

    unsafe {
        _mm512_storeu_si512(pt, arg1);
        _mm512_storeu_si512(pt.add(1), arg2);
    }
}

/// Given inputs:
/// - `arg1 = _mm512_set_epi64(15, 14, 13, 12, 11, 10, 9, 8)`
/// - `arg2 = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0)`
///
/// Writes `out = {8, 9, 10, 11, 0, 1, 2, 3, 12, 13, 14, 15, 4, 5, 6, 7}`.
#[target_feature(enable = "avx512f,avx")]
#[inline]
pub fn write_inv_interleaved_t4(arg1: __m512i, arg2: __m512i, out: &mut [u64; 16]) {
    let x0 = _mm512_extracti64x4_epi64(arg1, 0);
    let x1 = _mm512_extracti64x4_epi64(arg1, 1);
    let y0 = _mm512_extracti64x4_epi64(arg2, 0);
    let y1 = _mm512_extracti64x4_epi64(arg2, 1);

    let pt: *mut __m256i = out.as_mut_ptr().cast();

    unsafe {
        _mm256_storeu_si256(pt, x0);
        _mm256_storeu_si256(pt.add(1), y0);
        _mm256_storeu_si256(pt.add(2), x1);
        _mm256_storeu_si256(pt.add(3), y1);
    }
}

// Returns `_mm512_set_epi64(arg[3], arg[3], arg[2], arg[2], arg[1], arg[1], arg[0], arg[0])`
#[target_feature(enable = "avx512f,avx2")]
#[inline]
pub fn load_w_op_t2(arg: &[u64; 4]) -> __m512i {
    let vperm_w_idx: __m512i = _mm512_set_epi64(3, 3, 2, 2, 1, 1, 0, 0);
    let v_w_256: __m256i = unsafe { _mm256_loadu_si256(arg.as_ptr().cast()) };
    let v_w: __m512i = _mm512_broadcast_i64x4(v_w_256);
    _mm512_permutexvar_epi64(vperm_w_idx, v_w)
}

// Returns `_mm512_set_epi64(arg[1], arg[1], arg[1], arg[1], arg[0], arg[0], arg[0], arg[0])`
#[target_feature(enable = "avx512dq,avx512f,sse2")]
#[inline]
pub fn load_w_op_t4(arg: &[u64; 2]) -> __m512i {
    let vperm_w_idx: __m512i = _mm512_set_epi64(1, 1, 1, 1, 0, 0, 0, 0);
    let v_w_128: __m128i = unsafe { _mm_loadu_si128(arg.as_ptr().cast()) };
    let v_w: __m512i = _mm512_broadcast_i64x2(v_w_128);
    _mm512_permutexvar_epi64(vperm_w_idx, v_w)
}

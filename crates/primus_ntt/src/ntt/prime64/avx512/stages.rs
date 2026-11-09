//! Packed stage kernels corresponding to HEXL's `FwdT*` and `InvT*` helpers.
//!
//! `T` is the distance between the two operands of a radix-2 butterfly. T1,
//! T2, and T4 need lane permutations; T8 and larger distances use contiguous
//! eight-lane loads. The root slices are already arranged for the lane order
//! expected by each helper.

use core::arch::x86_64::*;

use super::butterfly::{fwd_butterfly, inv_butterfly};
use super::utils::*;

pub fn fwd_t1<const BIT_SHIFT: u32, const REDUCE_OUTPUT: bool>(
    operand: &mut [u64],
    v_modulus: __m512i,
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    unsafe {
        for ((x, v_w), v_w_precon) in operand
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<8>())
            .zip(w_precon.as_chunks_unchecked::<8>())
        {
            let (mut v_x, mut v_y) = load_fwd_interleaved_t1(x);

            let v_w = _mm512_loadu_si512(v_w.as_ptr().cast());
            let v_w_precon = _mm512_loadu_si512(v_w_precon.as_ptr().cast());

            fwd_butterfly::<BIT_SHIFT, false>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            if REDUCE_OUTPUT {
                v_x = _mm512_hexl_small_mod_epu64_2(v_x, v_twice_mod);
                v_x = _mm512_hexl_small_mod_epu64_2(v_x, v_modulus);
                v_y = _mm512_hexl_small_mod_epu64_2(v_y, v_twice_mod);
                v_y = _mm512_hexl_small_mod_epu64_2(v_y, v_modulus);
            }

            write_fwd_interleaved_t1(v_x, v_y, x);
        }
    }
}

pub fn fwd_t2<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    unsafe {
        for ((x, v_w), v_w_precon) in operand
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<8>())
            .zip(w_precon.as_chunks_unchecked::<8>())
        {
            let (mut v_x, mut v_y) = load_fwd_interleaved_t2(x);

            let v_w = _mm512_loadu_si512(v_w.as_ptr().cast());
            let v_w_precon = _mm512_loadu_si512(v_w_precon.as_ptr().cast());

            fwd_butterfly::<BIT_SHIFT, false>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            let v_x_pt: *mut __m512i = x.as_mut_ptr().cast();

            _mm512_storeu_si512(v_x_pt, v_x);
            _mm512_storeu_si512(v_x_pt.add(1), v_y);
        }
    }
}

pub fn fwd_t4<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    unsafe {
        for ((x, v_w), v_w_precon) in operand
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<8>())
            .zip(w_precon.as_chunks_unchecked::<8>())
        {
            let (mut v_x, mut v_y) = load_fwd_interleaved_t4(x);

            let v_w = _mm512_loadu_si512(v_w.as_ptr().cast());
            let v_w_precon = _mm512_loadu_si512(v_w_precon.as_ptr().cast());

            fwd_butterfly::<BIT_SHIFT, false>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            let v_x_pt: *mut __m512i = x.as_mut_ptr().cast();

            _mm512_storeu_si512(v_x_pt, v_x);
            _mm512_storeu_si512(v_x_pt.add(1), v_y);
        }
    }
}

pub fn fwd_t8_inplace<const BIT_SHIFT: u32, const INPUT_LESS_THAN_MOD: bool>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    t: usize,
    w: &[u64],
    w_precon: &[u64],
) {
    for ((chunk, &w), &w_precon) in operand.chunks_exact_mut(t << 1).zip(w).zip(w_precon) {
        unsafe {
            let (x, y) = chunk.split_at_mut_unchecked(t);
            let v_w = _mm512_set1_epi64(w as i64);
            let v_w_precon = _mm512_set1_epi64(w_precon as i64);

            for (x_chunk, y_chunk) in x
                .as_chunks_unchecked_mut::<8>()
                .iter_mut()
                .zip(y.as_chunks_unchecked_mut::<8>())
            {
                let mut v_x = _mm512_loadu_si512(x_chunk.as_ptr().cast());
                let mut v_y = _mm512_loadu_si512(y_chunk.as_ptr().cast());

                fwd_butterfly::<BIT_SHIFT, INPUT_LESS_THAN_MOD>(
                    &mut v_x,
                    &mut v_y,
                    v_w,
                    v_w_precon,
                    v_neg_modulus,
                    v_twice_mod,
                );

                _mm512_storeu_si512(x_chunk.as_mut_ptr().cast(), v_x);
                _mm512_storeu_si512(y_chunk.as_mut_ptr().cast(), v_y);
            }
        }
    }
}

pub fn inv_t1<const BIT_SHIFT: u32, const INPUT_LESS_THAN_MOD: bool>(
    x: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    // n >= 16 and n is power of 2
    unsafe {
        for ((chunk, w_chunk), w_precon_chunk) in x
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<8>())
            .zip(w_precon.as_chunks_unchecked::<8>())
        {
            let (mut v_x, mut v_y) = load_inv_interleaved_t1(chunk);

            let v_w = _mm512_loadu_si512(w_chunk.as_ptr().cast());
            let v_w_precon = _mm512_loadu_si512(w_precon_chunk.as_ptr().cast());

            inv_butterfly::<BIT_SHIFT, INPUT_LESS_THAN_MOD>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            let v_x_pt: *mut __m512i = chunk.as_mut_ptr().cast();

            _mm512_storeu_si512(v_x_pt, v_x);
            _mm512_storeu_si512(v_x_pt.add(1), v_y);
        }
    }
}

pub fn inv_t2<const BIT_SHIFT: u32>(
    x: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    // n >= 16 and n is power of 2
    unsafe {
        for ((chunk, w_chunk), w_precon_chunk) in x
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<4>())
            .zip(w_precon.as_chunks_unchecked::<4>())
        {
            let (mut v_x, mut v_y) = load_inv_interleaved_t2(chunk);

            let v_w = load_w_op_t2(w_chunk);
            let v_w_precon = load_w_op_t2(w_precon_chunk);

            inv_butterfly::<BIT_SHIFT, false>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            let v_x_pt: *mut __m512i = chunk.as_mut_ptr().cast();

            _mm512_storeu_si512(v_x_pt, v_x);
            _mm512_storeu_si512(v_x_pt.add(1), v_y);
        }
    }
}

pub fn inv_t4<const BIT_SHIFT: u32>(
    x: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    w: &[u64],
    w_precon: &[u64],
) {
    // n >= 16 and n is power of 2
    unsafe {
        for ((chunk, w_chunk), w_precon_chunk) in x
            .as_chunks_unchecked_mut::<16>()
            .iter_mut()
            .zip(w.as_chunks_unchecked::<2>())
            .zip(w_precon.as_chunks_unchecked::<2>())
        {
            let (mut v_x, mut v_y) = load_inv_interleaved_t4(chunk);

            let v_w = load_w_op_t4(w_chunk);
            let v_w_precon = load_w_op_t4(w_precon_chunk);

            inv_butterfly::<BIT_SHIFT, false>(
                &mut v_x,
                &mut v_y,
                v_w,
                v_w_precon,
                v_neg_modulus,
                v_twice_mod,
            );

            write_inv_interleaved_t4(v_x, v_y, chunk);
        }
    }
}

pub fn inv_t8<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    t: usize,
    w: &[u64],
    w_precon: &[u64],
) {
    // `t` is at least eight here, so both halves contain complete vectors.
    for ((chunk, &w), &w_precon) in operand.chunks_exact_mut(t << 1).zip(w).zip(w_precon) {
        let (x, y) = unsafe { chunk.split_at_mut_unchecked(t) };

        unsafe {
            let v_w = _mm512_set1_epi64(w as i64);
            let v_w_precon = _mm512_set1_epi64(w_precon as i64);

            for (x_chunk, y_chunk) in x
                .as_chunks_unchecked_mut::<8>()
                .iter_mut()
                .zip(y.as_chunks_unchecked_mut::<8>())
            {
                let mut v_x = _mm512_loadu_si512(x_chunk.as_ptr().cast());
                let mut v_y = _mm512_loadu_si512(y_chunk.as_ptr().cast());

                inv_butterfly::<BIT_SHIFT, false>(
                    &mut v_x,
                    &mut v_y,
                    v_w,
                    v_w_precon,
                    v_neg_modulus,
                    v_twice_mod,
                );

                _mm512_storeu_si512(x_chunk.as_mut_ptr().cast(), v_x);
                _mm512_storeu_si512(y_chunk.as_mut_ptr().cast(), v_y);
            }
        }
    }
}

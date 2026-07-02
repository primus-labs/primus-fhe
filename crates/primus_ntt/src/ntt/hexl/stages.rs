use core::arch::x86_64::*;

use super::butterfly::{fwd_butterfly, inv_butterfly};
use super::utils::*;

// ── Forward T1 ────────────────────────────────────────────────────────────

pub fn fwd_t1<const BIT_SHIFT: u32>(
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

            write_fwd_interleaved_t1(v_x, v_y, x);
        }
    }
}

// ── Forward T2 ────────────────────────────────────────────────────────────

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

// ── Forward T4 ────────────────────────────────────────────────────────────

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

// ── Forward T8 ────────────────────────────────────────────────────────────

pub fn fwd_t8_inplace<const BIT_SHIFT: u32, const INPUT_LESS_THAN_MOD: bool>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    t: usize,
    w: &[u64],
    w_precon: &[u64],
) {
    let mut w_iter = w.iter().copied();
    let mut w_precon_iter = w_precon.iter().copied();

    for chunk in operand.chunks_exact_mut(t << 1) {
        unsafe {
            let (x, y) = chunk.split_at_mut_unchecked(t);

            // Weights and weights' preconditions
            let v_w: __m512i = _mm512_set1_epi64(w_iter.next().unwrap() as i64);
            let v_w_precon: __m512i = _mm512_set1_epi64(w_precon_iter.next().unwrap() as i64);

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

// ── Inverse T1 ────────────────────────────────────────────────────────────

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

// ── Inverse T2 ────────────────────────────────────────────────────────────

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

// ── Inverse T4 ────────────────────────────────────────────────────────────

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

// ── Inverse T8 ────────────────────────────────────────────────────────────

pub fn inv_t8<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    v_neg_modulus: __m512i,
    v_twice_mod: __m512i,
    t: usize,
    w: &[u64],
    w_precon: &[u64],
) {
    let mut w_iter = w.iter().copied();
    let mut w_precon_iter = w_precon.iter().copied();

    // assume 8 | t
    for chunk in operand.chunks_exact_mut(t << 1) {
        let (x, y) = unsafe { chunk.split_at_mut_unchecked(t) };

        unsafe {
            let v_w = _mm512_set1_epi64(w_iter.next().unwrap() as i64);
            let v_w_precon = _mm512_set1_epi64(w_precon_iter.next().unwrap() as i64);

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

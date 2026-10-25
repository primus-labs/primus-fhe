use core::arch::x86_64::*;

use super::super::U32NttTable;
use super::arithmetic::{mul_mod_lazy_avx512, reduce_once_avx512, reduce_twice_avx512};
use super::butterfly::{fwd_butterfly_avx512, inv_butterfly_avx512};
use super::permute::{
    t1_load_xy, t1_store_xy, t2_load_xy, t2_store_xy, t4_load_xy, t4_store_xy, t8_load_xy,
    t8_store_xy,
};

#[target_feature(enable = "avx512f")]
#[inline]
unsafe fn load_twiddle_vector(
    roots: &[u32],
    roots_precon: &[u32],
    index: usize,
) -> (__m512i, __m512i) {
    unsafe {
        (
            _mm512_loadu_si512(roots.as_ptr().add(index).cast()),
            _mm512_loadu_si512(roots_precon.as_ptr().add(index).cast()),
        )
    }
}

impl U32NttTable {
    /// Forward NTT (radix-2, Cooley-Tukey, in-place) — AVX-512 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX-512F is available at runtime
    /// (e.g. via `is_x86_feature_detected!("avx512f")`).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two and >= 32.
    /// - `roots.len() == values.len()` and `roots_precon.len() == values.len()`.
    /// - `q < 2^30`.
    #[target_feature(enable = "avx512f")]
    pub(crate) unsafe fn avx512_forward_transform(
        &self,
        values: &mut [u32],
        output_mod_factor: u32,
    ) {
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 4,
            "output_mod_factor must be 1 or 4; got {output_mod_factor}"
        );

        let n = self.poly_length.get();
        let q = self.q;
        let two_q = self.two_q;

        let roots = self.roots.as_slice();
        let roots_precon = self.roots_precon.as_slice();
        let avx512_roots = self.avx512_roots.as_slice();
        let avx512_roots_precon = self.avx512_roots_precon.as_slice();

        let v_q = _mm512_set1_epi32(q as i32);
        let v_two_q = _mm512_set1_epi32(two_q as i32);

        let mut ri = 1usize; // skip roots[0] = 1 (for T16 broadcast stages)
        let mut avx_ri = 0usize; // index into pre-expanded arrays

        let mut t = n >> 1;

        while t != 0 {
            if t >= 16 {
                // Broadcast one twiddle across sixteen contiguous butterflies.
                for block in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *roots.get_unchecked(ri) };
                    let wp = unsafe { *roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm512_set1_epi32(w as i32);
                    let v_wp = _mm512_set1_epi32(wp as i32);

                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };
                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<16>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<16>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                        let v_y =
                            unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };
                        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        unsafe {
                            _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_x);
                            _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_y);
                        }
                    }
                }
            } else if t == 8 {
                // T8 and smaller stages use pre-expanded twiddle vectors.
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) =
                        unsafe { load_twiddle_vector(avx512_roots, avx512_roots_precon, avx_ri) };
                    avx_ri += 16;
                    let (v_x, v_y) = t8_load_xy(chunk);
                    let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t8_store_xy(v_x, v_y, chunk);
                }
            } else if t == 4 {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) =
                        unsafe { load_twiddle_vector(avx512_roots, avx512_roots_precon, avx_ri) };
                    avx_ri += 16;
                    let (v_x, v_y) = t4_load_xy(chunk);
                    let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t4_store_xy(v_x, v_y, chunk);
                }
            } else if t == 2 {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) =
                        unsafe { load_twiddle_vector(avx512_roots, avx512_roots_precon, avx_ri) };
                    avx_ri += 16;

                    let (v_x, v_y) = t2_load_xy(chunk);
                    let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t2_store_xy(v_x, v_y, chunk);
                }
            } else {
                debug_assert_eq!(t, 1);
                if output_mod_factor == 1 {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                    for chunk in chunks {
                        let (v_w, v_wp) = unsafe {
                            load_twiddle_vector(avx512_roots, avx512_roots_precon, avx_ri)
                        };
                        avx_ri += 16;

                        let (v_x, v_y) = t1_load_xy(chunk);
                        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        let v_x = reduce_twice_avx512(v_x, v_q, v_two_q);
                        let v_y = reduce_twice_avx512(v_y, v_q, v_two_q);
                        t1_store_xy(v_x, v_y, chunk);
                    }
                } else {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                    for chunk in chunks {
                        let (v_w, v_wp) = unsafe {
                            load_twiddle_vector(avx512_roots, avx512_roots_precon, avx_ri)
                        };
                        avx_ri += 16;

                        let (v_x, v_y) = t1_load_xy(chunk);
                        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        t1_store_xy(v_x, v_y, chunk);
                    }
                }
            }
            t >>= 1;
        }
    }

    /// Inverse NTT (radix-2, Gentleman-Sande, in-place) — AVX-512 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX-512F is available at runtime
    /// (e.g. via `is_x86_feature_detected!("avx512f")`).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two and >= 32.
    /// - `inv_roots.len() == values.len()` and `inv_roots_precon.len() == values.len()`.
    /// - `q < 2^30`.
    #[target_feature(enable = "avx512f")]
    pub(crate) unsafe fn avx512_inverse_transform(
        &self,
        values: &mut [u32],
        output_mod_factor: u32,
    ) {
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 2,
            "output_mod_factor must be 1 or 2; got {output_mod_factor}"
        );

        let n = self.poly_length.get();
        let q = self.q;
        let two_q = self.two_q;

        let inv_roots = self.inv_roots.as_slice();
        let inv_roots_precon = self.inv_roots_precon.as_slice();
        let avx512_inv_roots = self.avx512_inv_roots.as_slice();
        let avx512_inv_roots_precon = self.avx512_inv_roots_precon.as_slice();
        let inv_n = self.inv_n;
        let inv_n_precon = self.inv_n_precon;
        let inv_n_w = self.inv_n_w;
        let inv_n_w_precon = self.inv_n_w_precon;

        let v_q = _mm512_set1_epi32(q as i32);
        let v_two_q = _mm512_set1_epi32(two_q as i32);

        let mut ri = 1usize; // skip inv_roots[0] = 1 (for T16 broadcast)
        let mut avx_ri = 0usize; // index into pre-expanded arrays

        let mut t = 1usize;
        let mut m = n >> 1;

        while m > 1 {
            if t >= 16 {
                // Broadcast one twiddle across sixteen contiguous butterflies.
                for block in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *inv_roots.get_unchecked(ri) };
                    let wp = unsafe { *inv_roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm512_set1_epi32(w as i32);
                    let v_wp = _mm512_set1_epi32(wp as i32);

                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };
                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<16>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<16>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                        let v_y =
                            unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };
                        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        unsafe {
                            _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_x);
                            _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_y);
                        }
                    }
                }
            } else if t == 8 {
                // T8 and smaller stages use pre-expanded twiddle vectors.
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) = unsafe {
                        load_twiddle_vector(avx512_inv_roots, avx512_inv_roots_precon, avx_ri)
                    };
                    avx_ri += 16;
                    let (v_x, v_y) = t8_load_xy(chunk);
                    let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t8_store_xy(v_x, v_y, chunk);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else if t == 4 {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) = unsafe {
                        load_twiddle_vector(avx512_inv_roots, avx512_inv_roots_precon, avx_ri)
                    };
                    avx_ri += 16;

                    let (v_x, v_y) = t4_load_xy(chunk);
                    let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t4_store_xy(v_x, v_y, chunk);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else if t == 2 {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) = unsafe {
                        load_twiddle_vector(avx512_inv_roots, avx512_inv_roots_precon, avx_ri)
                    };
                    avx_ri += 16;

                    let (v_x, v_y) = t2_load_xy(chunk);
                    let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t2_store_xy(v_x, v_y, chunk);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else {
                debug_assert_eq!(t, 1);
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let (v_w, v_wp) = unsafe {
                        load_twiddle_vector(avx512_inv_roots, avx512_inv_roots_precon, avx_ri)
                    };
                    avx_ri += 16;

                    let (v_x, v_y) = t1_load_xy(chunk);
                    let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    t1_store_xy(v_x, v_y, chunk);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            }
            t <<= 1;
            m >>= 1;
        }

        // Fuse the final butterfly with multiplication by inv_n.
        let v_inv_n = _mm512_set1_epi32(inv_n as i32);
        let v_inv_n_w = _mm512_set1_epi32(inv_n_w as i32);
        let v_inv_n_precon = _mm512_set1_epi32(inv_n_precon as i32);
        let v_inv_n_w_precon = _mm512_set1_epi32(inv_n_w_precon as i32);

        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<16>() };
        let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<16>() };
        if output_mod_factor == 1 {
            for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                let v_x = unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                let v_y = unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };

                let v_sum = _mm512_add_epi32(v_x, v_y);
                let v_tx = reduce_once_avx512(v_sum, v_two_q);
                let v_ty = _mm512_sub_epi32(_mm512_add_epi32(v_x, v_two_q), v_y);

                let v_new_x = reduce_once_avx512(
                    mul_mod_lazy_avx512(v_tx, v_inv_n, v_inv_n_precon, v_q),
                    v_q,
                );
                let v_new_y = reduce_once_avx512(
                    mul_mod_lazy_avx512(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q),
                    v_q,
                );

                unsafe {
                    _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_new_x);
                    _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_new_y);
                }
            }
        } else {
            for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                let v_x = unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                let v_y = unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };

                let v_sum = _mm512_add_epi32(v_x, v_y);
                let v_tx = reduce_once_avx512(v_sum, v_two_q);
                let v_ty = _mm512_sub_epi32(_mm512_add_epi32(v_x, v_two_q), v_y);

                let v_new_x = mul_mod_lazy_avx512(v_tx, v_inv_n, v_inv_n_precon, v_q);
                let v_new_y = mul_mod_lazy_avx512(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q);

                unsafe {
                    _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_new_x);
                    _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_new_y);
                }
            }
        }
    }
}

use core::arch::x86_64::*;

use super::super::U32NttTable;
use super::arithmetic::{mul_mod_lazy_avx512, reduce_once_avx512};
use super::butterfly::{fwd_butterfly_avx512, inv_butterfly_avx512};
use super::permute::{
    deinterleave_fwd_t1, deinterleave_fwd_t2, deinterleave_fwd_t4, deinterleave_fwd_t8,
    deinterleave_inv_t1, deinterleave_inv_t2, deinterleave_inv_t4, deinterleave_inv_t8,
};

impl U32NttTable {
    // ---------------------------------------------------------------------------
    // Transform functions
    // ---------------------------------------------------------------------------

    /// Forward NTT (radix-2, Cooley-Tukey, in-place) — AVX-512 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX-512F is available at runtime
    /// (e.g. via [`HAS_AVX512F`]).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two and ≥ 64.
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

        let n = self.n;
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
        let mut m = 1;

        while m < n {
            if t >= 16 {
                // --- AVX-512 path: t ≥ 16, process 16 butterflies at a time ---
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
                // --- AVX-512 T8: pre-expanded vector load ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_roots_precon.as_ptr().add(avx_ri).cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;
                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_fwd_t8(ptr, v_w, v_wp, v_q, v_two_q);
                }
            } else if t == 4 {
                // --- AVX-512 T4: shuffle load / 2-stage shuffle store ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_roots_precon.as_ptr().add(avx_ri).cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;
                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_fwd_t4(ptr, v_w, v_wp, v_q, v_two_q);
                }
            } else if t == 2 {
                // --- AVX-512 T2: unpack load/store, pre-expanded vector load ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_roots_precon.as_ptr().add(avx_ri).cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;

                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_fwd_t2(ptr, v_w, v_wp, v_q, v_two_q);
                }
            } else {
                debug_assert_eq!(t, 1);
                // --- AVX-512 T1: shuffle+unpack load/store, pre-expanded vector load ---
                if output_mod_factor == 1 {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                    for chunk in chunks {
                        let v_w = unsafe {
                            _mm512_loadu_si512(avx512_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                        };
                        let v_wp = unsafe {
                            _mm512_loadu_si512(
                                avx512_roots_precon.as_ptr().add(avx_ri).cast::<__m512i>(),
                            )
                        };
                        avx_ri += 16;

                        let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                        deinterleave_fwd_t1::<true>(ptr, v_w, v_wp, v_q, v_two_q);
                    }
                } else {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                    for chunk in chunks {
                        let v_w = unsafe {
                            _mm512_loadu_si512(avx512_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                        };
                        let v_wp = unsafe {
                            _mm512_loadu_si512(
                                avx512_roots_precon.as_ptr().add(avx_ri).cast::<__m512i>(),
                            )
                        };
                        avx_ri += 16;

                        let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                        deinterleave_fwd_t1::<false>(ptr, v_w, v_wp, v_q, v_two_q);
                    }
                }
            }
            t >>= 1;
            m <<= 1;
        }
    }

    /// Inverse NTT (radix-2, Gentleman-Sande, in-place) — AVX-512 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX-512F is available at runtime
    /// (e.g. via [`HAS_AVX512F`]).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two.
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

        let n = self.n;
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
                // --- AVX-512 path ---
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
                // --- AVX-512 T8: pre-expanded vector load ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_inv_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_inv_roots_precon
                                .as_ptr()
                                .add(avx_ri)
                                .cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;
                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_inv_t8(ptr, v_w, v_wp, v_q, v_two_q);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else if t == 4 {
                // --- AVX-512 T4: shuffle load / 2-stage shuffle store ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_inv_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_inv_roots_precon
                                .as_ptr()
                                .add(avx_ri)
                                .cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;

                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_inv_t4(ptr, v_w, v_wp, v_q, v_two_q);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else if t == 2 {
                // --- AVX-512 T2: unpack load/store, pre-expanded vector load ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_inv_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_inv_roots_precon
                                .as_ptr()
                                .add(avx_ri)
                                .cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;

                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_inv_t2(ptr, v_w, v_wp, v_q, v_two_q);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            } else {
                debug_assert_eq!(t, 1);
                // --- AVX-512 T1: shuffle+unpack load/store, pre-expanded vector load ---
                let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
                for chunk in chunks {
                    let v_w = unsafe {
                        _mm512_loadu_si512(avx512_inv_roots.as_ptr().add(avx_ri).cast::<__m512i>())
                    };
                    let v_wp = unsafe {
                        _mm512_loadu_si512(
                            avx512_inv_roots_precon
                                .as_ptr()
                                .add(avx_ri)
                                .cast::<__m512i>(),
                        )
                    };
                    avx_ri += 16;

                    let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                    deinterleave_inv_t1(ptr, v_w, v_wp, v_q, v_two_q);
                }
                ri += m; // keep ri tracking scalar root position for T16+ broadcast
            }
            t <<= 1;
            m >>= 1;
        }

        // --- Final stage: fused with inv_n multiply (inv_n_w precomputed) ---
        // --- 512-bit final stage: n/2 ≥ 32 (guaranteed since n ≥ 64) ---
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

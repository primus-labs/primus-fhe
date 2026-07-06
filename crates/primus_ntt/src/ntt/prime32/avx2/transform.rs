use core::arch::x86_64::*;

use super::super::U32NttTable;
use super::arithmetic::{mul_mod_lazy_avx2, reduce_once_avx2, reduce_twice_avx2};
use super::butterfly::{fwd_butterfly_avx2, inv_butterfly_avx2};
use super::permute::{t1_load_xy, t1_store_xy, t2_load_xy, t2_store_xy, t4_load_xy, t4_store_xy};

impl U32NttTable {
    // ---------------------------------------------------------------------------
    // Transform functions
    // ---------------------------------------------------------------------------

    /// Forward NTT (radix-2, Cooley-Tukey, in-place) — AVX2 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX2 is available at runtime
    /// (e.g. via [`HAS_AVX2`]).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two and ≥ 32.
    /// - `roots.len() == values.len()` and `roots_precon.len() == values.len()`.
    /// - `q < 2^30`.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn avx2_forward_transform(&self, values: &mut [u32], output_mod_factor: u32) {
        let n = self.n;
        assert_eq!(values.len(), n);

        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 4,
            "output_mod_factor must be 1 or 4; got {output_mod_factor}"
        );

        let q = self.q;
        let two_q = self.two_q;

        let roots = self.roots.as_slice();
        let roots_precon = self.roots_precon.as_slice();
        let avx2_roots = self.avx2_roots.as_slice();
        let avx2_roots_precon = self.avx2_roots_precon.as_slice();

        let v_q = _mm256_set1_epi32(q as i32);
        let v_two_q = _mm256_set1_epi32(two_q as i32);

        let mut ri = 1usize; // skip roots[0] = 1 (for T8 broadcast stages)
        let mut avx_ri = 0usize; // index into pre-expanded arrays

        let mut t = n >> 1;
        let mut m = 1;

        while m < n {
            if t >= 8 {
                // --- AVX2 path: t ≥ 8, process 8 butterflies per inner iteration ---
                for block in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *roots.get_unchecked(ri) };
                    let wp = unsafe { *roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm256_set1_epi32(w as i32);
                    let v_wp = _mm256_set1_epi32(wp as i32);

                    // SAFETY: block.len() == 2t, t ≥ 8.
                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };

                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<8>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<8>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let v_y =
                            unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        unsafe {
                            _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_x);
                            _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_y);
                        }
                    }
                }
            } else {
                // --- t < 8 stages (n ≥ 32 guaranteed, all AVX2) ---
                match t {
                    4 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        for chunk in chunks {
                            let v_w = unsafe {
                                _mm256_loadu_si256(
                                    avx2_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = unsafe {
                                _mm256_loadu_si256(
                                    avx2_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            avx_ri += 8;
                            ri += 2; // keep ri tracking scalar root position for T1

                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t4_load_xy(ptr, unsafe { ptr.add(1) });
                            let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t4_store_xy(v_x, v_y, ptr, unsafe { ptr.add(1) });
                        }
                    }
                    2 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        for chunk in chunks {
                            let v_w = unsafe {
                                _mm256_loadu_si256(
                                    avx2_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = unsafe {
                                _mm256_loadu_si256(
                                    avx2_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            avx_ri += 8;
                            ri += 4; // keep ri tracking scalar root position for T1

                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t2_load_xy(ptr);
                            let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t2_store_xy(v_x, v_y, ptr);
                        }
                    }
                    1 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        if output_mod_factor == 1 {
                            for chunk in chunks {
                                let v_w = unsafe {
                                    _mm256_loadu_si256(
                                        avx2_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                    )
                                };
                                let v_wp = unsafe {
                                    _mm256_loadu_si256(
                                        avx2_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                    )
                                };
                                avx_ri += 8;
                                ri += 8;
                                let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                                let (v_x, v_y) = t1_load_xy(ptr);
                                let (v_x, v_y) =
                                    fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                                let v_x = reduce_twice_avx2(v_x, v_q, v_two_q);
                                let v_y = reduce_twice_avx2(v_y, v_q, v_two_q);
                                t1_store_xy(v_x, v_y, ptr);
                            }
                        } else {
                            for chunk in chunks {
                                let v_w = unsafe {
                                    _mm256_loadu_si256(
                                        avx2_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                    )
                                };
                                let v_wp = unsafe {
                                    _mm256_loadu_si256(
                                        avx2_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                    )
                                };
                                avx_ri += 8;
                                ri += 8;
                                let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                                let (v_x, v_y) = t1_load_xy(ptr);
                                let (v_x, v_y) =
                                    fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                                t1_store_xy(v_x, v_y, ptr);
                            }
                        }
                    }
                    _ => unreachable!("t < 8 and t is a power of two => t ∈ {{1, 2, 4}}"),
                }
            }
            t >>= 1;
            m <<= 1;
        }
    }

    /// Inverse NTT (radix-2, Gentleman-Sande, in-place) — AVX2 only.
    ///
    /// # Safety
    ///
    /// The caller MUST ensure AVX2 is available at runtime
    /// (e.g. via [`HAS_AVX2`]).
    ///
    /// # Preconditions (caller MUST uphold; not checked)
    ///
    /// - `values.len()` is a power of two.
    /// - `inv_roots.len() == values.len()` and `inv_roots_precon.len() == values.len()`.
    /// - `q < 2^30`.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn avx2_inverse_transform(&self, values: &mut [u32], output_mod_factor: u32) {
        let n = self.n;
        assert_eq!(values.len(), n);

        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 2,
            "output_mod_factor must be 1 or 2; got {output_mod_factor}"
        );

        let q = self.q;
        let two_q = self.two_q;

        let inv_roots = self.inv_roots.as_slice();
        let inv_roots_precon = self.inv_roots_precon.as_slice();
        let avx2_inv_roots = self.avx2_inv_roots.as_slice();
        let avx2_inv_roots_precon = self.avx2_inv_roots_precon.as_slice();
        let inv_n = self.inv_n;
        let inv_n_precon = self.inv_n_precon;
        let inv_n_w = self.inv_n_w;
        let inv_n_w_precon = self.inv_n_w_precon;

        let v_q = _mm256_set1_epi32(q as i32);
        let v_two_q = _mm256_set1_epi32(two_q as i32);

        let mut ri = 1usize; // skip inv_roots[0] = 1 (for T8 broadcast stages)
        let mut avx_ri = 0usize; // index into pre-expanded arrays

        let mut t = 1usize;
        let mut m = n >> 1;

        while m > 1 {
            if t >= 8 {
                // --- AVX2 path ---
                for block in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *inv_roots.get_unchecked(ri) };
                    let wp = unsafe { *inv_roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm256_set1_epi32(w as i32);
                    let v_wp = _mm256_set1_epi32(wp as i32);

                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };
                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<8>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<8>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let v_y =
                            unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let (v_x, v_y) = inv_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        unsafe {
                            _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_x);
                            _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_y);
                        }
                    }
                }
            } else {
                // --- t < 8 stages ---
                match t {
                    1 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        for chunk in chunks {
                            let v_w = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            avx_ri += 8;
                            ri += 8;
                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t1_load_xy(ptr);
                            let (v_x, v_y) = inv_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t1_store_xy(v_x, v_y, ptr);
                        }
                    }
                    2 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        for chunk in chunks {
                            let v_w = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            avx_ri += 8;
                            ri += 4; // keep ri tracking scalar root position for T8+ broadcast
                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t2_load_xy(ptr);
                            let (v_x, v_y) = inv_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t2_store_xy(v_x, v_y, ptr);
                        }
                    }
                    4 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                        for chunk in chunks {
                            let v_w = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = unsafe {
                                _mm256_loadu_si256(
                                    avx2_inv_roots_precon.as_ptr().add(avx_ri).cast::<__m256i>(),
                                )
                            };
                            avx_ri += 8;
                            ri += 2; // keep ri tracking scalar root position for T8+ broadcast
                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t4_load_xy(ptr, unsafe { ptr.add(1) });
                            let (v_x, v_y) = inv_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t4_store_xy(v_x, v_y, ptr, unsafe { ptr.add(1) });
                        }
                    }
                    _ => unreachable!("t < 8 and t is a power of two => t ∈ {{1, 2, 4}}"),
                }
            }
            t <<= 1;
            m >>= 1;
        }

        // --- Final stage: fused with inv_n multiply (inv_n_w precomputed) ---
        // --- AVX2 final stage: n/2 ≥ 16 (guaranteed since n ≥ 32) ---
        let v_inv_n = _mm256_set1_epi32(inv_n as i32);
        let v_inv_n_w = _mm256_set1_epi32(inv_n_w as i32);
        let v_inv_n_precon = _mm256_set1_epi32(inv_n_precon as i32);
        let v_inv_n_w_precon = _mm256_set1_epi32(inv_n_w_precon as i32);

        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<8>() };
        let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<8>() };
        if output_mod_factor == 1 {
            for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                let v_x = unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                let v_y = unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };

                let v_sum = _mm256_add_epi32(v_x, v_y);
                let v_tx = reduce_once_avx2(v_sum, v_two_q);
                let v_ty = _mm256_sub_epi32(_mm256_add_epi32(v_x, v_two_q), v_y);

                let v_new_x =
                    reduce_once_avx2(mul_mod_lazy_avx2(v_tx, v_inv_n, v_inv_n_precon, v_q), v_q);
                let v_new_y = reduce_once_avx2(
                    mul_mod_lazy_avx2(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q),
                    v_q,
                );

                unsafe {
                    _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_new_x);
                    _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_new_y);
                }
            }
        } else {
            for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                let v_x = unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                let v_y = unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };

                let v_sum = _mm256_add_epi32(v_x, v_y);
                let v_tx = reduce_once_avx2(v_sum, v_two_q);
                let v_ty = _mm256_sub_epi32(_mm256_add_epi32(v_x, v_two_q), v_y);

                let v_new_x = mul_mod_lazy_avx2(v_tx, v_inv_n, v_inv_n_precon, v_q);
                let v_new_y = mul_mod_lazy_avx2(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q);

                unsafe {
                    _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_new_x);
                    _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_new_y);
                }
            }
        }
    }
}

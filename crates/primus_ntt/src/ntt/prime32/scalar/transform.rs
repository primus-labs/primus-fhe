use super::super::U32NttTable;
use super::arithmetic::{fwd_butterfly, inv_butterfly, mul_mod_lazy, reduce_once, reduce_twice};

impl U32NttTable {
    /// Forward NTT (radix-2, Cooley-Tukey, in-place).
    ///
    /// Input: normal order, coefficients in `[0, 4q)`.
    /// Output: bit-reversed order.
    ///
    /// `output_mod_factor`:
    /// - `4`: output in `[0, 4q)` (lazy)
    /// - `1`: output in `[0, q)` (canonical)
    pub fn scalar_forward_transform(&self, values: &mut [u32], output_mod_factor: u32) {
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 4,
            "output_mod_factor must be 1 or 4; got {output_mod_factor}"
        );

        let n = self.n;
        let q = self.q;
        let two_q = self.two_q;

        let roots = self.roots.as_slice();
        let roots_precon = self.roots_precon.as_slice();

        // Direct index: avoid zip+map overhead. Equivalent to AoS access.
        let mut ri = 1usize; // skip roots[0]

        let mut t = n >> 1;
        let mut m = 1;
        while m < n {
            // SAFETY: ri + (n / (2*t)) stays within roots.len() = n.
            match t {
                8 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<16>();
                    for chunk in chunks {
                        let w = *roots.get_unchecked(ri);
                        let wp = *roots_precon.get_unchecked(ri);
                        ri += 1;

                        let [
                            x0,
                            x1,
                            x2,
                            x3,
                            x4,
                            x5,
                            x6,
                            x7,
                            y0,
                            y1,
                            y2,
                            y3,
                            y4,
                            y5,
                            y6,
                            y7,
                        ] = chunk;

                        fwd_butterfly(x0, y0, w, wp, q, two_q);
                        fwd_butterfly(x1, y1, w, wp, q, two_q);
                        fwd_butterfly(x2, y2, w, wp, q, two_q);
                        fwd_butterfly(x3, y3, w, wp, q, two_q);
                        fwd_butterfly(x4, y4, w, wp, q, two_q);
                        fwd_butterfly(x5, y5, w, wp, q, two_q);
                        fwd_butterfly(x6, y6, w, wp, q, two_q);
                        fwd_butterfly(x7, y7, w, wp, q, two_q);
                    }
                },
                4 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<8>();
                    for chunk in chunks {
                        let w = *roots.get_unchecked(ri);
                        let wp = *roots_precon.get_unchecked(ri);
                        ri += 1;

                        let [x0, x1, x2, x3, y0, y1, y2, y3] = chunk;

                        fwd_butterfly(x0, y0, w, wp, q, two_q);
                        fwd_butterfly(x1, y1, w, wp, q, two_q);
                        fwd_butterfly(x2, y2, w, wp, q, two_q);
                        fwd_butterfly(x3, y3, w, wp, q, two_q);
                    }
                },
                2 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<4>();
                    for chunk in chunks {
                        let w = *roots.get_unchecked(ri);
                        let wp = *roots_precon.get_unchecked(ri);
                        ri += 1;

                        let [x0, x1, y0, y1] = chunk;

                        fwd_butterfly(x0, y0, w, wp, q, two_q);
                        fwd_butterfly(x1, y1, w, wp, q, two_q);
                    }
                },
                1 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<2>();
                    if output_mod_factor == 1 {
                        for chunk in chunks {
                            let w = *roots.get_unchecked(ri);
                            let wp = *roots_precon.get_unchecked(ri);
                            ri += 1;
                            let [x, y] = chunk;
                            fwd_butterfly(x, y, w, wp, q, two_q);
                            *x = reduce_twice(*x, q, two_q);
                            *y = reduce_twice(*y, q, two_q);
                        }
                    } else {
                        for chunk in chunks {
                            let w = *roots.get_unchecked(ri);
                            let wp = *roots_precon.get_unchecked(ri);
                            ri += 1;
                            let [x, y] = chunk;
                            fwd_butterfly(x, y, w, wp, q, two_q);
                        }
                    }
                },
                _ => {
                    for chunk in values.chunks_exact_mut(t * 2) {
                        let w = unsafe { *roots.get_unchecked(ri) };
                        let wp = unsafe { *roots_precon.get_unchecked(ri) };
                        ri += 1;
                        let (xs, ys) = chunk.split_at_mut(t);
                        for (x, y) in xs.iter_mut().zip(ys) {
                            fwd_butterfly(x, y, w, wp, q, two_q);
                        }
                    }
                }
            }
            t >>= 1;
            m <<= 1;
        }
    }

    /// Inverse NTT (radix-2, Gentleman-Sande, in-place).
    ///
    /// Input: bit-reversed order, coefficients in `[0, 2q)`.
    /// Output: normal order.
    ///
    /// The final stage fuses multiplication by `inv_n` for both halves.
    ///
    /// `output_mod_factor`:
    /// - `2`: output in `[0, 2q)` (lazy)
    /// - `1`: output in `[0, q)` (canonical)
    pub fn scalar_inverse_transform(&self, values: &mut [u32], output_mod_factor: u32) {
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 2,
            "output_mod_factor must be 1 or 2; got {output_mod_factor}"
        );

        let n = self.n;
        let q = self.q;
        let two_q = self.two_q;

        let inv_n = self.inv_n;
        let inv_n_precon = self.inv_n_precon;
        let inv_n_w = self.inv_n_w;
        let inv_n_w_precon = self.inv_n_w_precon;
        let inv_roots = self.inv_roots.as_slice();
        let inv_roots_precon = self.inv_roots_precon.as_slice();

        // Direct index, skip inv_roots[0]
        let mut ri = 1usize;

        let mut t = 1usize;
        let mut m = n >> 1;
        while m > 1 {
            match t {
                1 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<2>();
                    for chunk in chunks {
                        let w = *inv_roots.get_unchecked(ri);
                        let wp = *inv_roots_precon.get_unchecked(ri);
                        ri += 1;
                        let [x, y] = chunk;
                        inv_butterfly(x, y, w, wp, q, two_q);
                    }
                },
                2 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<4>();
                    for chunk in chunks {
                        let w = *inv_roots.get_unchecked(ri);
                        let wp = *inv_roots_precon.get_unchecked(ri);
                        ri += 1;
                        let [x0, x1, y0, y1] = chunk;
                        inv_butterfly(x0, y0, w, wp, q, two_q);
                        inv_butterfly(x1, y1, w, wp, q, two_q);
                    }
                },
                4 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<8>();
                    for chunk in chunks {
                        let w = *inv_roots.get_unchecked(ri);
                        let wp = *inv_roots_precon.get_unchecked(ri);
                        ri += 1;
                        let [x0, x1, x2, x3, y0, y1, y2, y3] = chunk;
                        inv_butterfly(x0, y0, w, wp, q, two_q);
                        inv_butterfly(x1, y1, w, wp, q, two_q);
                        inv_butterfly(x2, y2, w, wp, q, two_q);
                        inv_butterfly(x3, y3, w, wp, q, two_q);
                    }
                },
                8 => unsafe {
                    let chunks = values.as_chunks_unchecked_mut::<16>();
                    for chunk in chunks {
                        let w = *inv_roots.get_unchecked(ri);
                        let wp = *inv_roots_precon.get_unchecked(ri);
                        ri += 1;
                        let [
                            x0,
                            x1,
                            x2,
                            x3,
                            x4,
                            x5,
                            x6,
                            x7,
                            y0,
                            y1,
                            y2,
                            y3,
                            y4,
                            y5,
                            y6,
                            y7,
                        ] = chunk;
                        inv_butterfly(x0, y0, w, wp, q, two_q);
                        inv_butterfly(x1, y1, w, wp, q, two_q);
                        inv_butterfly(x2, y2, w, wp, q, two_q);
                        inv_butterfly(x3, y3, w, wp, q, two_q);
                        inv_butterfly(x4, y4, w, wp, q, two_q);
                        inv_butterfly(x5, y5, w, wp, q, two_q);
                        inv_butterfly(x6, y6, w, wp, q, two_q);
                        inv_butterfly(x7, y7, w, wp, q, two_q);
                    }
                },
                _ => {
                    for chunk in values.chunks_exact_mut(t * 2) {
                        let w = unsafe { *inv_roots.get_unchecked(ri) };
                        let wp = unsafe { *inv_roots_precon.get_unchecked(ri) };
                        ri += 1;
                        let (xs, ys) = chunk.split_at_mut(t);
                        for (x, y) in xs.iter_mut().zip(ys) {
                            inv_butterfly(x, y, w, wp, q, two_q);
                        }
                    }
                }
            }
            t <<= 1;
            m >>= 1;
        }

        // Final stage: multiply by inv_n and inv_n_w (precomputed).
        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        if output_mod_factor == 1 {
            for (x, y) in xs.iter_mut().zip(ys) {
                let tx = reduce_once(x.wrapping_add(*y), two_q);
                let ty = x.wrapping_add(two_q).wrapping_sub(*y);
                *x = reduce_once(mul_mod_lazy(tx, inv_n, inv_n_precon, q), q);
                *y = reduce_once(mul_mod_lazy(ty, inv_n_w, inv_n_w_precon, q), q);
            }
        } else {
            for (x, y) in xs.iter_mut().zip(ys) {
                let tx = reduce_once(x.wrapping_add(*y), two_q);
                let ty = x.wrapping_add(two_q).wrapping_sub(*y);
                *x = mul_mod_lazy(tx, inv_n, inv_n_precon, q);
                *y = mul_mod_lazy(ty, inv_n_w, inv_n_w_precon, q);
            }
        }
    }
}

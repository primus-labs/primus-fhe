/// Returns `x mod q`, assuming `x < 2 * q`.
///
/// Branchless: `x.min(x.wrapping_sub(q))`.  For unsigned values this is
/// correct because `x < q` makes `x - q` wrap large so `min` keeps `x`,
/// while `x >= q` produces the reduced value.
#[inline(always)]
pub fn reduce_once(x: u32, q: u32) -> u32 {
    debug_assert!(x < 2 * q);
    x.min(x.wrapping_sub(q))
}

/// Returns `x mod q`, assuming `x < 4 * q`.
/// `two_q` must equal `2 * q`.
#[inline(always)]
pub fn reduce_twice(x: u32, q: u32, two_q: u32) -> u32 {
    debug_assert_eq!(two_q, 2 * q);
    debug_assert!(x < 4 * q);
    reduce_once(reduce_once(x, two_q), q)
}

/// Plain Barrett lazy multiply for u32 with 32-bit shift.
///
/// Matches `ShoupFactor<u32>::lazy_factor_mul_modulo`: 1 widening
/// multiply for the high-half quotient, then 2 low-32 multiplies and a
/// 32-bit wrapping subtract.  The Harvey/Shoup bound guarantees the
/// result fits in `[0, 2q)`, and `q < 2^30` keeps `[0, 4q)` operands
/// safe.
#[inline(always)]
pub(super) fn mul_mod_lazy(y: u32, w: u32, w_precon: u32, q: u32) -> u32 {
    let qhat = ((y as u64).wrapping_mul(w_precon as u64) >> 32) as u32;
    w.wrapping_mul(y).wrapping_sub(q.wrapping_mul(qhat))
}

/// Forward NTT (radix-2, Cooley-Tukey, in-place).
///
/// Input: normal order, coefficients in `[0, 4q)`.
/// Output: bit-reversed order.
///
/// Note: uses Barrett lazy multiply with `q < 2^30` guarantee. The final
/// reduction (when `output_mod_factor == 1`) brings `[0, 4q)` -> `[0, q)`.
///
/// `input_mod_factor`:
/// - `1`: input in `[0, q)`
/// - `2`: input in `[0, 2q)`
/// - `4`: input in `[0, 4q)`
///
/// `output_mod_factor`:
/// - `4`: output in `[0, 4q)` (lazy)
/// - `1`: output in `[0, q)` (canonical)
#[allow(clippy::too_many_arguments)]
pub fn forward_transform(
    values: &mut [u32],
    q: u32,
    two_q: u32,
    roots: &[u32],
    roots_precon: &[u32],
    input_mod_factor: u32,
    output_mod_factor: u32,
) {
    debug_assert!(
        matches!(input_mod_factor, 1 | 2 | 4),
        "input_mod_factor must be 1, 2 or 4; got {input_mod_factor}"
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 4,
        "output_mod_factor must be 1 or 4; got {output_mod_factor}"
    );

    let n = values.len();

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
                for chunk in chunks {
                    let w = *roots.get_unchecked(ri);
                    let wp = *roots_precon.get_unchecked(ri);
                    ri += 1;

                    let [x, y] = chunk;

                    fwd_butterfly(x, y, w, wp, q, two_q);
                }
            },
            _ => {
                for chunk in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *roots.get_unchecked(ri) };
                    let wp = unsafe { *roots_precon.get_unchecked(ri) };
                    ri += 1;
                    let (xs, ys) = chunk.split_at_mut(t);
                    for (x, y) in xs.iter_mut().zip(ys.iter_mut()) {
                        fwd_butterfly(x, y, w, wp, q, two_q);
                    }
                }
            }
        }
        t >>= 1;
        m <<= 1;
    }

    if output_mod_factor == 1 {
        values.iter_mut().for_each(|x| {
            *x = reduce_twice(*x, q, two_q);
        });
    }
}

/// Plain Harvey forward butterfly — no ShoupFactor construction in the
/// hot path.
#[inline(always)]
pub(super) fn fwd_butterfly(x: &mut u32, y: &mut u32, w: u32, wp: u32, q: u32, two_q: u32) {
    let tx = reduce_once(*x, two_q);
    let t = mul_mod_lazy(*y, w, wp, q);
    *x = tx + t;
    *y = tx + two_q - t;
}

/// Plain Harvey inverse butterfly — no ShoupFactor construction in the
/// hot path.
#[inline(always)]
pub(super) fn inv_butterfly(x: &mut u32, y: &mut u32, w: u32, wp: u32, q: u32, two_q: u32) {
    let tx = *x + *y;
    let y_red = *x + two_q - *y;
    *x = reduce_once(tx, two_q);
    *y = mul_mod_lazy(y_red, w, wp, q);
}

/// Inverse NTT (radix-2, Gentleman-Sande, in-place).
///
/// Input: bit-reversed order, coefficients in `[0, 2q)`.
/// Output: normal order.
///
/// The final stage fuses multiplication by `inv_n` for both halves.
///
/// Note: uses Barrett lazy multiply with `q < 2^30` guarantee.
///
/// `input_mod_factor`:
/// - `1`: input in `[0, q)`
/// - `2`: input in `[0, 2q)`
///
/// `output_mod_factor`:
/// - `2`: output in `[0, 2q)` (lazy)
/// - `1`: output in `[0, q)` (canonical)
#[allow(clippy::too_many_arguments)]
pub fn inverse_transform(
    values: &mut [u32],
    q: u32,
    two_q: u32,
    inv_n: u32,
    inv_n_precon: u32,
    inv_roots: &[u32],
    inv_roots_precon: &[u32],
    input_mod_factor: u32,
    output_mod_factor: u32,
) {
    debug_assert!(
        input_mod_factor == 1 || input_mod_factor == 2,
        "input_mod_factor must be 1 or 2; got {input_mod_factor}"
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 2,
        "output_mod_factor must be 1 or 2; got {output_mod_factor}"
    );

    let n = values.len();

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
                    for (x, y) in xs.iter_mut().zip(ys.iter_mut()) {
                        inv_butterfly(x, y, w, wp, q, two_q);
                    }
                }
            }
        }
        t <<= 1;
        m >>= 1;
    }

    // Final stage: multiply by inv_n and inv_n * last_w.
    let last_w = unsafe { *inv_roots.get_unchecked(ri) };
    // last_wp at same index is not needed for the final stage.

    let inv_n_w = mul_mod_lazy(last_w, inv_n, inv_n_precon, q);
    let inv_n_w = reduce_once(inv_n_w, q);
    let inv_n_w_precon = (((inv_n_w as u64) << 32) / q as u64) as u32;

    let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
    for (x, y) in xs.iter_mut().zip(ys.iter_mut()) {
        let tx = reduce_once(x.wrapping_add(*y), two_q);
        let ty = x.wrapping_add(two_q).wrapping_sub(*y);
        *x = mul_mod_lazy(tx, inv_n, inv_n_precon, q);
        *y = mul_mod_lazy(ty, inv_n_w, inv_n_w_precon, q);
    }

    if output_mod_factor == 1 {
        values.iter_mut().for_each(|x| {
            *x = reduce_once(*x, q);
        });
    }
}

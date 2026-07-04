/// Returns `x mod q`, assuming `x < 2 * q`.
///
/// Branchless: `x.min(x.wrapping_sub(q))`.
#[inline(always)]
pub fn reduce_once(x: u64, q: u64) -> u64 {
    debug_assert!(x < 2 * q);
    x.min(x.wrapping_sub(q))
}

/// Returns `x mod q`, assuming `x < 4 * q`.
/// `two_q` must equal `2 * q`.
#[inline(always)]
pub fn reduce_twice(x: u64, q: u64, two_q: u64) -> u64 {
    debug_assert_eq!(two_q, 2 * q);
    debug_assert!(x < 4 * q);
    reduce_once(reduce_once(x, two_q), q)
}

/// Plain Barrett lazy multiply for u64 with 64-bit shift.
///
/// Matches `ShoupFactor<u64>::lazy_factor_mul_modulo` without constructing a
/// factor object in the hot path. The result is congruent to `y * w (mod q)`
/// and stays in `[0, 2q)` for Harvey lazy operands when `q < 2^62`.
#[inline(always)]
pub(super) fn mul_mod_lazy(y: u64, w: u64, w_precon: u64, q: u64) -> u64 {
    let qhat = ((y as u128).wrapping_mul(w_precon as u128) >> 64) as u64;
    w.wrapping_mul(y).wrapping_sub(q.wrapping_mul(qhat))
}

#[inline(always)]
fn quotient_for(w: u64, q: u64) -> u64 {
    (((w as u128) << 64) / q as u128) as u64
}

/// Harvey forward butterfly (radix-2).
///
/// Assumes `*x` and `*y` are in `[0, 4q)`.
/// Output: `*x` and `*y` are in `[0, 4q)` such that
/// `x' = x + W*y (mod q)`, `y' = x - W*y (mod q)`.
#[inline(always)]
pub fn fwd_butterfly(x: &mut u64, y: &mut u64, w: u64, w_precon: u64, q: u64, two_q: u64) {
    let tx = reduce_once(*x, two_q);
    let t = mul_mod_lazy(*y, w, w_precon, q);
    *x = tx + t;
    *y = tx + two_q - t;
}

/// Harvey inverse butterfly (radix-2).
///
/// Assumes `*x` and `*y` are in `[0, 2q)`.
/// Output: `*x` and `*y` are in `[0, 2q)` such that
/// `x' = x + y (mod q)`, `y' = W * (x - y) (mod q)`.
#[inline(always)]
pub fn inv_butterfly(x: &mut u64, y: &mut u64, w: u64, w_precon: u64, q: u64, two_q: u64) {
    let tx = *x + *y;
    let y_red = *x + two_q - *y;
    *x = reduce_once(tx, two_q);
    *y = mul_mod_lazy(y_red, w, w_precon, q);
}

/// Forward NTT (radix-2, Cooley-Tukey, in-place).
///
/// Input: normal order, coefficients in `[0, 4q)`.
/// Output: bit-reversed order.
///
/// Note: uses Barrett lazy multiply with lazy operands (up to `4q`).
/// The Barrett formula remains correct because `q < 2^62` guarantees all
/// intermediate products fit in `u128`.
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
    values: &mut [u64],
    q: u64,
    two_q: u64,
    roots: &[u64],
    roots_precon: &[u64],
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

    let mut w_iter = roots.iter().copied();
    let mut wp_iter = roots_precon.iter().copied();
    w_iter.next(); // skip roots[0]
    wp_iter.next(); // skip roots_precon[0]

    let mut t = n >> 1;
    let mut m = 1;
    while m < n {
        match t {
            8 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

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
            }
            4 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x0, x1, x2, x3, y0, y1, y2, y3] = chunk;

                    fwd_butterfly(x0, y0, w, wp, q, two_q);
                    fwd_butterfly(x1, y1, w, wp, q, two_q);
                    fwd_butterfly(x2, y2, w, wp, q, two_q);
                    fwd_butterfly(x3, y3, w, wp, q, two_q);
                }
            }
            2 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<4>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x0, x1, y0, y1] = chunk;

                    fwd_butterfly(x0, y0, w, wp, q, two_q);
                    fwd_butterfly(x1, y1, w, wp, q, two_q);
                }
            }
            1 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<2>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x, y] = chunk;

                    fwd_butterfly(x, y, w, wp, q, two_q);
                }
            }
            _ => {
                for chunk in values.chunks_exact_mut(t * 2) {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();
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

/// Inverse NTT (radix-2, Gentleman-Sande, in-place).
///
/// Input: bit-reversed order, coefficients in `[0, 2q)`.
/// Output: normal order.
///
/// The final stage fuses multiplication by `inv_n` for both halves.
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
    values: &mut [u64],
    q: u64,
    two_q: u64,
    inv_n: u64,
    inv_n_precon: u64,
    inv_roots: &[u64],
    inv_roots_precon: &[u64],
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

    let mut w_iter = inv_roots.iter().copied();
    let mut wp_iter = inv_roots_precon.iter().copied();
    w_iter.next(); // skip inv_roots[0]
    wp_iter.next(); // skip inv_roots_precon[0]

    let mut t = 1usize;
    let mut m = n >> 1;
    while m > 1 {
        match t {
            1 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<2>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x, y] = chunk;

                    inv_butterfly(x, y, w, wp, q, two_q);
                }
            }
            2 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<4>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x0, x1, y0, y1] = chunk;

                    inv_butterfly(x0, y0, w, wp, q, two_q);
                    inv_butterfly(x1, y1, w, wp, q, two_q);
                }
            }
            4 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

                    let [x0, x1, x2, x3, y0, y1, y2, y3] = chunk;

                    inv_butterfly(x0, y0, w, wp, q, two_q);
                    inv_butterfly(x1, y1, w, wp, q, two_q);
                    inv_butterfly(x2, y2, w, wp, q, two_q);
                    inv_butterfly(x3, y3, w, wp, q, two_q);
                }
            }
            8 => {
                let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();

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
            }
            _ => {
                for chunk in values.chunks_exact_mut(t * 2) {
                    let w = w_iter.next().unwrap();
                    let wp = wp_iter.next().unwrap();
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
    let last_w = w_iter.next().unwrap();

    let inv_n_w = reduce_once(mul_mod_lazy(last_w, inv_n, inv_n_precon, q), q);
    let inv_n_w_precon = quotient_for(inv_n_w, q);

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

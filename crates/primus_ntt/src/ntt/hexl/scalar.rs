use primus_factor::MultiplyFactor;

use crate::ntt::hexl::{
    internal::check_arguments,
    number_theory::{multiply_mod_lazy, reduce_once, reduce_twice},
};

/// Out-of-place Harvey butterfly: assume `X`, `Y` in `[0, 4q)`, and return
/// `X`, `Y` in `[0, 4q)` such that
/// `X = X + W*Y (mod q)`, `Y = X - W*Y (mod q)`.
///
/// # Parameters
/// - `X`: Input butterfly data.
/// - `Y`: Input butterfly data.
/// - `W`: Root of unity.
/// - `W_precon`: Preconditioned `W` for `BitShift`-bit Barrett reduction.
/// - `modulus`: Negative modulus, i.e. `(-q)` represented as 8 64-bit signed integers in SIMD form.
/// - `twice_modulus`: Twice the modulus, i.e. `2*q` represented as 8 64-bit signed integers in SIMD form.
///
/// # Details
/// See Algorithm 4 of <https://arxiv.org/pdf/1205.2926.pdf>
#[inline]
pub fn fwd_butterfly_radix2(
    x: &mut u64,
    y: &mut u64,
    w: u64,
    w_precon: u64,
    modulus: u64,
    twice_modulus: u64,
) {
    let tx = reduce_once(*x, twice_modulus);
    let t = multiply_mod_lazy::<64>(*y, w, w_precon, modulus);

    *x = tx + t;
    *y = tx + twice_modulus - t;
}

pub fn forward_transform_to_bit_reverse_radix2_inplace(
    operand: &mut [u64],
    modulus: u64,
    root_of_unity_powers: &[u64],
    precon_root_of_unity_powers: &[u64],
    output_mod_factor: u32,
) {
    let n = operand.len();

    check_arguments(n, modulus);

    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 4,
        "output_mod_factor must be 1 or 4; got {output_mod_factor}"
    );

    let twice_modulus = modulus << 1;

    let mut w_iter = root_of_unity_powers.iter().copied();
    let mut w_precon_iter = precon_root_of_unity_powers.iter().copied();

    w_iter.next(); // skip w[0]
    w_precon_iter.next(); // skip w_precon[0]

    let mut t = n >> 1;
    let mut m = 1;
    while m < n {
        match t {
            8 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<16>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [
                        x_r0,
                        x_r1,
                        x_r2,
                        x_r3,
                        x_r4,
                        x_r5,
                        x_r6,
                        x_r7,
                        y_r0,
                        y_r1,
                        y_r2,
                        y_r3,
                        y_r4,
                        y_r5,
                        y_r6,
                        y_r7,
                    ] = chunk;

                    fwd_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r4, y_r4, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r5, y_r5, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r6, y_r6, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r7, y_r7, w, w_precon, modulus, twice_modulus);
                }
            }
            4 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<8>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r0, x_r1, x_r2, x_r3, y_r0, y_r1, y_r2, y_r3] = chunk;

                    fwd_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                }
            }
            2 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<4>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r0, x_r1, y_r0, y_r1] = chunk;

                    fwd_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    fwd_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                }
            }
            1 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<2>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r, y_r] = chunk;

                    fwd_butterfly_radix2(x_r, y_r, w, w_precon, modulus, twice_modulus);
                }
            }
            _ => {
                for chunk in operand.chunks_exact_mut(t * 2) {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let (x, y) = chunk.split_at_mut(t);

                    let x_chunks = unsafe { x.as_chunks_unchecked_mut::<8>() };
                    let y_chunks = unsafe { y.as_chunks_unchecked_mut::<8>() };

                    for (x_chunk, y_chunk) in x_chunks.iter_mut().zip(y_chunks.iter_mut()) {
                        let [x_r0, x_r1, x_r2, x_r3, x_r4, x_r5, x_r6, x_r7] = x_chunk;
                        let [y_r0, y_r1, y_r2, y_r3, y_r4, y_r5, y_r6, y_r7] = y_chunk;

                        fwd_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r4, y_r4, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r5, y_r5, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r6, y_r6, w, w_precon, modulus, twice_modulus);
                        fwd_butterfly_radix2(x_r7, y_r7, w, w_precon, modulus, twice_modulus);
                    }
                }
            }
        }
        t >>= 1;
        m <<= 1;
    }

    if output_mod_factor == 1 {
        operand.iter_mut().for_each(|x| {
            *x = reduce_twice(*x, modulus, twice_modulus);
        });
    }
}

/// In-place Harvey inverse butterfly (radix-2).
///
/// Assumptions:
/// - `*x` and `*y` are in `[0, 2q)`.
///
/// Output:
/// - After the call, `*x` and `*y` are in `[0, 2q)` such that
///   - `x := x + y (mod q)` (kept in the lazy range `[0, 2q)`)
///   - `y := W * (x_old - y_old) (mod q)` (also kept in `[0, 2q)`)
///
/// Notes:
/// - This corresponds to the Harvey butterfly form. See Algorithm 3 in
///   <https://arxiv.org/pdf/1205.2926.pdf>
///
/// Parameters:
/// - `w`: root of unity `W`
/// - `w_precon`: preconditioned `W` for 64-bit Barrett reduction
/// - `modulus`: `q`
/// - `twice_modulus`: `2*q`
#[inline]
pub fn inv_butterfly_radix2(
    x: &mut u64,
    y: &mut u64,
    w: u64,
    w_precon: u64,
    modulus: u64,
    twice_modulus: u64,
) {
    let tx = *x + *y;
    let y_r = *x + twice_modulus - *y;
    *x = reduce_once(tx, twice_modulus);
    *y = multiply_mod_lazy::<64>(y_r, w, w_precon, modulus);
}

pub fn inverse_transform_from_bit_reverse_radix2_inplace(
    operand: &mut [u64],
    modulus: u64,
    inv_n: u64,
    inv_root_of_unity_powers: &[u64],
    precon_inv_root_of_unity_powers: &[u64],
    output_mod_factor: u32,
) {
    let n = operand.len();
    check_arguments(n, modulus);
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 4,
        "output_mod_factor must be 1 or 4; got {output_mod_factor}"
    );

    let twice_modulus = modulus << 1;

    let mut w_iter = inv_root_of_unity_powers.iter().copied();
    let mut w_precon_iter = precon_inv_root_of_unity_powers.iter().copied();

    w_iter.next(); // skip w[0]
    w_precon_iter.next(); // skip w_precon[0]

    let mut t = 1;
    let mut m = n >> 1;
    while m > 1 {
        match t {
            1 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<2>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r, y_r] = chunk;

                    inv_butterfly_radix2(x_r, y_r, w, w_precon, modulus, twice_modulus);
                }
            }
            2 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<4>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r0, x_r1, y_r0, y_r1] = chunk;

                    inv_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                }
            }
            4 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<8>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [x_r0, x_r1, x_r2, x_r3, y_r0, y_r1, y_r2, y_r3] = chunk;

                    inv_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                }
            }
            8 => {
                let chunks = unsafe { operand.as_chunks_unchecked_mut::<16>() };
                for chunk in chunks {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let [
                        x_r0,
                        x_r1,
                        x_r2,
                        x_r3,
                        x_r4,
                        x_r5,
                        x_r6,
                        x_r7,
                        y_r0,
                        y_r1,
                        y_r2,
                        y_r3,
                        y_r4,
                        y_r5,
                        y_r6,
                        y_r7,
                    ] = chunk;

                    inv_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r4, y_r4, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r5, y_r5, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r6, y_r6, w, w_precon, modulus, twice_modulus);
                    inv_butterfly_radix2(x_r7, y_r7, w, w_precon, modulus, twice_modulus);
                }
            }
            _ => {
                for chunk in operand.chunks_exact_mut(t * 2) {
                    let w = w_iter.next().unwrap();
                    let w_precon = w_precon_iter.next().unwrap();

                    let (x, y) = chunk.split_at_mut(t);

                    let x_chunks = unsafe { x.as_chunks_unchecked_mut::<8>() };
                    let y_chunks = unsafe { y.as_chunks_unchecked_mut::<8>() };

                    for (x_chunk, y_chunk) in x_chunks.iter_mut().zip(y_chunks.iter_mut()) {
                        let [x_r0, x_r1, x_r2, x_r3, x_r4, x_r5, x_r6, x_r7] = x_chunk;
                        let [y_r0, y_r1, y_r2, y_r3, y_r4, y_r5, y_r6, y_r7] = y_chunk;

                        inv_butterfly_radix2(x_r0, y_r0, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r1, y_r1, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r2, y_r2, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r3, y_r3, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r4, y_r4, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r5, y_r5, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r6, y_r6, w, w_precon, modulus, twice_modulus);
                        inv_butterfly_radix2(x_r7, y_r7, w, w_precon, modulus, twice_modulus);
                    }
                }
            }
        }
        t <<= 1;
        m >>= 1;
    }

    let w = w_iter.next().unwrap();

    let mf_inv_n = MultiplyFactor::new(inv_n, 64, modulus);
    let inv_n_precon = mf_inv_n.quotient();

    let inv_n_w = mf_inv_n.mul_modulo::<64>(w, modulus);
    let mf_inv_n_w = MultiplyFactor::new(inv_n_w, 64, modulus);
    let inv_n_w_precon = mf_inv_n_w.quotient();

    let (x_chunk, y_chunk) = unsafe { operand.split_at_mut_unchecked(n / 2) };

    for (x, y) in x_chunk.iter_mut().zip(y_chunk) {
        // Assume X, Y in [0, 2q) and compute
        // X' = N^{-1} (X + Y) (mod q)
        // Y' = N^{-1} * W * (X - Y) (mod q)
        let tx = reduce_once(*x + *y, twice_modulus);
        let ty = *x + twice_modulus - *y;
        *x = multiply_mod_lazy::<64>(tx, inv_n, inv_n_precon, modulus);
        *y = multiply_mod_lazy::<64>(ty, inv_n_w, inv_n_w_precon, modulus);
    }

    if output_mod_factor == 1 {
        // Reduce from [0, 2q) to [0,q)
        operand.iter_mut().for_each(|x| {
            *x = reduce_once(*x, modulus);
        });
    }
}

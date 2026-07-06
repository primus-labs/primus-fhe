use core::arch::x86_64::*;

use primus_factor::MultiplyFactor;

use super::internal::{check_arguments, max_fwd_modulus, max_inv_modulus};
use super::stages::*;
use super::utils::*;

const BASE_NTT_SIZE: usize = 1024;

// ── Forward Transform ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub unsafe fn forward_transform_to_bit_reverse_avx512<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    modulus: u64,
    root_of_unity_powers: &[u64],
    precon_root_of_unity_powers: &[u64],
    input_mod_factor: u64,
    output_mod_factor: u64,
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = operand.len();

    check_arguments(n, modulus);
    debug_assert!(
        modulus < max_fwd_modulus(BIT_SHIFT),
        "modulus {modulus} too large for BitShift {BIT_SHIFT} => maximum value {}",
        max_fwd_modulus(BIT_SHIFT)
    );
    debug_assert!(
        n >= 16,
        "Don't support small transforms. Need n >= 16, got n = {n}"
    );
    debug_assert!(
        input_mod_factor == 1 || input_mod_factor == 2 || input_mod_factor == 4,
        "input_mod_factor must be 1, 2, or 4; got {input_mod_factor}"
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 4,
        "output_mod_factor must be 1 or 4; got {output_mod_factor}"
    );

    let twice_mod = modulus << 1;

    let v_modulus = unsafe { _mm512_set1_epi64(modulus as i64) };
    let v_neg_modulus = unsafe { _mm512_set1_epi64(-(modulus as i64)) };
    let v_twice_mod = unsafe { _mm512_set1_epi64(twice_mod as i64) };

    if n <= BASE_NTT_SIZE {
        // Perform breadth-first NTT
        let mut t = n >> 1;
        let mut m = 1;
        let mut w_idx = (m << recursion_depth) + (recursion_half * m);

        // First iteration assumes input in [0,p)
        if m < (n >> 3) {
            let w = &root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_root_of_unity_powers[w_idx..w_idx + m];

            if input_mod_factor <= 2 && recursion_depth == 0 {
                fwd_t8_inplace::<BIT_SHIFT, true>(
                    operand,
                    v_neg_modulus,
                    v_twice_mod,
                    t,
                    w,
                    w_precon,
                );
            } else {
                fwd_t8_inplace::<BIT_SHIFT, false>(
                    operand,
                    v_neg_modulus,
                    v_twice_mod,
                    t,
                    w,
                    w_precon,
                );
            }

            t >>= 1;
            m <<= 1;
            w_idx <<= 1;
        }

        while m < (n >> 3) {
            let w = &root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_root_of_unity_powers[w_idx..w_idx + m];

            fwd_t8_inplace::<BIT_SHIFT, false>(operand, v_neg_modulus, v_twice_mod, t, w, w_precon);

            t >>= 1;
            m <<= 1;
            w_idx <<= 1;
        }

        // Do T=4, T=2, T=1 separately
        {
            // Correction step needed due to extra copies of roots of unity in the
            // AVX512 vectors loaded for FwdT2 and FwdT4
            let compute_new_w_idx = |idx: usize| {
                // Originally, from root of unity vector index to loop:
                // [0, N/8) => FwdT8
                // [N/8, N/4) => FwdT4
                // [N/4, N/2) => FwdT2
                // [N/2, N) => FwdT1
                // The new mapping from AVX512 root of unity vector index to loop:
                // [0, N/8) => FwdT8
                // [N/8, 5N/8) => FwdT4
                // [5N/8, 9N/8) => FwdT2
                // [9N/8, 13N/8) => FwdT1
                let n = n << recursion_depth;

                // FwdT8 range
                if idx <= n / 8 {
                    return idx;
                }
                // FwdT4 range
                if idx <= n / 4 {
                    return (idx - n / 8) * 4 + (n / 8);
                }
                // FwdT2 range
                if idx <= n / 2 {
                    return (idx - n / 4) * 2 + (5 * n / 8);
                }
                // FwdT1 range
                idx + (5 * n / 8)
            };

            let mut new_w_idx = compute_new_w_idx(w_idx);
            let mut w = &root_of_unity_powers[new_w_idx..new_w_idx + m * 4];
            let mut w_precon = &precon_root_of_unity_powers[new_w_idx..new_w_idx + m * 4];
            fwd_t4::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, w, w_precon);

            m <<= 1;
            w_idx <<= 1;
            new_w_idx = compute_new_w_idx(w_idx);
            w = &root_of_unity_powers[new_w_idx..new_w_idx + m * 2];
            w_precon = &precon_root_of_unity_powers[new_w_idx..new_w_idx + m * 2];
            fwd_t2::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, w, w_precon);

            m <<= 1;
            w_idx <<= 1;
            new_w_idx = compute_new_w_idx(w_idx);
            w = &root_of_unity_powers[new_w_idx..new_w_idx + m];
            w_precon = &precon_root_of_unity_powers[new_w_idx..new_w_idx + m];
            fwd_t1::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, w, w_precon);
        }

        if output_mod_factor == 1 {
            // n power of two at least 8 => n divisible by 8
            unsafe {
                for chunk in operand.as_chunks_unchecked_mut::<8>() {
                    let mut v_x = _mm512_loadu_si512(chunk.as_ptr().cast());

                    // Reduce from [0, 4q) to [0, q)
                    v_x = _mm512_hexl_small_mod_epu64_2(v_x, v_twice_mod);
                    v_x = _mm512_hexl_small_mod_epu64_2(v_x, v_modulus);

                    _mm512_storeu_si512(chunk.as_mut_ptr().cast(), v_x);
                }
            }
        }
    } else {
        // Perform depth-first NTT via recursive call
        let t = n >> 1;
        let w_idx = (1 << recursion_depth) + recursion_half;
        let w = &root_of_unity_powers[w_idx..w_idx + 1];
        let w_precon = &precon_root_of_unity_powers[w_idx..w_idx + 1];

        fwd_t8_inplace::<BIT_SHIFT, false>(operand, v_neg_modulus, v_twice_mod, t, w, w_precon);

        unsafe {
            let (left, right) = operand.split_at_mut_unchecked(n / 2);

            forward_transform_to_bit_reverse_avx512::<BIT_SHIFT>(
                left,
                modulus,
                root_of_unity_powers,
                precon_root_of_unity_powers,
                input_mod_factor,
                output_mod_factor,
                recursion_depth + 1,
                recursion_half * 2,
            );

            forward_transform_to_bit_reverse_avx512::<BIT_SHIFT>(
                right,
                modulus,
                root_of_unity_powers,
                precon_root_of_unity_powers,
                input_mod_factor,
                output_mod_factor,
                recursion_depth + 1,
                recursion_half * 2 + 1,
            );
        }
    }
}

// ── Inverse Transform ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub unsafe fn inverse_transform_from_bit_reverse_avx512<const BIT_SHIFT: u32>(
    operand: &mut [u64],
    modulus: u64,
    inv_n: u64,
    inv_root_of_unity_powers: &[u64],
    precon_inv_root_of_unity_powers: &[u64],
    input_mod_factor: u64,
    output_mod_factor: u64,
    recursion_depth: usize,
    recursion_half: usize,
) {
    let n = operand.len();

    check_arguments(n, modulus);
    debug_assert!(
        n >= 16,
        "inverse_transform_from_bit_reverse_avx512 doesn't support small transforms. Need n >= 16, got n = {n}"
    );
    debug_assert!(
        modulus < max_inv_modulus(BIT_SHIFT),
        "modulus {modulus} too large for BitShift {BIT_SHIFT} => maximum value {}",
        max_inv_modulus(BIT_SHIFT)
    );

    debug_assert!(
        input_mod_factor == 1 || input_mod_factor == 2,
        "input_mod_factor must be 1 or 2; got {input_mod_factor}",
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 2,
        "output_mod_factor must be 1 or 2; got {output_mod_factor}",
    );

    let twice_mod = modulus << 1;
    let v_modulus = unsafe { _mm512_set1_epi64(modulus as i64) };
    let v_neg_modulus = unsafe { _mm512_set1_epi64(-(modulus as i64)) };
    let v_twice_mod = unsafe { _mm512_set1_epi64(twice_mod as i64) };

    let mut t = 1;
    let mut m = n >> 1;
    let mut w_idx = 1 + m * recursion_half;

    if n <= BASE_NTT_SIZE {
        // Perform breadth-first InvNTT

        // Extract t=1, t=2, t=4 loops separately
        {
            // t = 1
            let w = &inv_root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_inv_root_of_unity_powers[w_idx..w_idx + m];

            if input_mod_factor == 1 && recursion_depth == 0 {
                inv_t1::<BIT_SHIFT, true>(operand, v_neg_modulus, v_twice_mod, w, w_precon);
            } else {
                inv_t1::<BIT_SHIFT, false>(operand, v_neg_modulus, v_twice_mod, w, w_precon);
            }

            t <<= 1;
            m >>= 1;
            let mut w_idx_delta = m * ((1 << (recursion_depth + 1)) - recursion_half);
            w_idx += w_idx_delta;

            // t = 2
            let w = &inv_root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_inv_root_of_unity_powers[w_idx..w_idx + m];
            inv_t2::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, w, w_precon);

            t <<= 1;
            m >>= 1;
            w_idx_delta >>= 1;
            w_idx += w_idx_delta;

            // t = 4
            let w = &inv_root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_inv_root_of_unity_powers[w_idx..w_idx + m];
            inv_t4::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, w, w_precon);

            t <<= 1;
            m >>= 1;
            w_idx_delta >>= 1;
            w_idx += w_idx_delta;

            // t >= 8
            while m > 1 {
                let w = &inv_root_of_unity_powers[w_idx..w_idx + m];
                let w_precon = &precon_inv_root_of_unity_powers[w_idx..w_idx + m];
                inv_t8::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, t, w, w_precon);
                t <<= 1;
                m >>= 1;
                w_idx_delta >>= 1;
                w_idx += w_idx_delta;
            }
        }
    } else {
        unsafe {
            let (left, right) = operand.split_at_mut_unchecked(n / 2);
            inverse_transform_from_bit_reverse_avx512::<BIT_SHIFT>(
                left,
                modulus,
                inv_n,
                inv_root_of_unity_powers,
                precon_inv_root_of_unity_powers,
                input_mod_factor,
                output_mod_factor,
                recursion_depth + 1,
                recursion_half * 2,
            );
            inverse_transform_from_bit_reverse_avx512::<BIT_SHIFT>(
                right,
                modulus,
                inv_n,
                inv_root_of_unity_powers,
                precon_inv_root_of_unity_powers,
                input_mod_factor,
                output_mod_factor,
                recursion_depth + 1,
                recursion_half * 2 + 1,
            );
        }

        let mut w_idx_delta = m * ((1 << (recursion_depth + 1)) - recursion_half);
        while m > 2 {
            t <<= 1;
            m >>= 1;
            w_idx_delta >>= 1;
            w_idx += w_idx_delta;
        }
        if m == 2 {
            let w = &inv_root_of_unity_powers[w_idx..w_idx + m];
            let w_precon = &precon_inv_root_of_unity_powers[w_idx..w_idx + m];
            inv_t8::<BIT_SHIFT>(operand, v_neg_modulus, v_twice_mod, t, w, w_precon);
            w_idx_delta >>= 1;
            w_idx += w_idx_delta;
        }
    }

    // Final loop through data
    if recursion_depth == 0 {
        let w = inv_root_of_unity_powers[w_idx];
        let mf_inv_n = MultiplyFactor::new(inv_n, BIT_SHIFT, modulus);
        let inv_n_prime = mf_inv_n.quotient();

        let inv_n_w = mf_inv_n.mul_modulo::<BIT_SHIFT>(w, modulus);
        let mf_inv_n_w = MultiplyFactor::new(inv_n_w, BIT_SHIFT, modulus);
        let inv_n_w_prime = mf_inv_n_w.quotient();

        unsafe {
            let (x, y) = operand.split_at_mut_unchecked(n / 2);

            let v_inv_n = _mm512_set1_epi64(inv_n as i64);
            let v_inv_n_prime = _mm512_set1_epi64(inv_n_prime as i64);
            let v_inv_n_w = _mm512_set1_epi64(inv_n_w as i64);
            let v_inv_n_w_prime = _mm512_set1_epi64(inv_n_w_prime as i64);

            // Merge final InvNTT loop with modulus reduction baked-in
            for (x_chunk, y_chunk) in x
                .as_chunks_unchecked_mut::<8>()
                .iter_mut()
                .zip(y.as_chunks_unchecked_mut::<8>())
            {
                let mut v_x = _mm512_loadu_si512(x_chunk.as_ptr().cast());
                let mut v_y = _mm512_loadu_si512(y_chunk.as_ptr().cast());

                // Slightly different from regular InvButterfly because different W is
                // used for X and Y
                let y_minus_2q = _mm512_sub_epi64(v_y, v_twice_mod);
                let x_plus_y_mod2q = _mm512_hexl_small_add_mod_epi64(v_x, v_y, v_twice_mod);
                // T = *X + twice_mod - *Y
                let t = _mm512_sub_epi64(v_x, y_minus_2q);

                if BIT_SHIFT == 32 {
                    let mut q1 = _mm512_hexl_mullo_epi_64(v_inv_n_prime, x_plus_y_mod2q);
                    q1 = _mm512_srli_epi64::<32>(q1);
                    // X = inv_N * X_plus_Y_mod2q - Q1 * modulus;
                    let inv_n_tx = _mm512_hexl_mullo_epi_64(v_inv_n, x_plus_y_mod2q);
                    v_x = _mm512_hexl_mullo_add_lo_epi_64(inv_n_tx, q1, v_neg_modulus);

                    let mut q2 = _mm512_hexl_mullo_epi_64(v_inv_n_w_prime, t);
                    q2 = _mm512_srli_epi64::<32>(q2);

                    // Y = inv_N_W * T - Q2 * modulus;
                    let inv_n_w_t = _mm512_hexl_mullo_epi_64(v_inv_n_w, t);
                    v_y = _mm512_hexl_mullo_add_lo_epi_64(inv_n_w_t, q2, v_neg_modulus);
                } else if BIT_SHIFT == 52 {
                    let q1 = _mm512_hexl_mulhi_epi_52(v_inv_n_prime, x_plus_y_mod2q);
                    // X = inv_N * X_plus_Y_mod2q - Q1 * modulus;
                    let inv_n_tx = _mm512_hexl_mullo_epi_52(v_inv_n, x_plus_y_mod2q);
                    v_x = _mm512_hexl_mullo_add_lo_epi_52(inv_n_tx, q1, v_neg_modulus);

                    let q2 = _mm512_hexl_mulhi_epi_52(v_inv_n_w_prime, t);
                    // Y = inv_N_W * T - Q2 * modulus;
                    let inv_n_w_t = _mm512_hexl_mullo_epi_52(v_inv_n_w, t);
                    v_y = _mm512_hexl_mullo_add_lo_epi_52(inv_n_w_t, q2, v_neg_modulus);
                } else if BIT_SHIFT == 64 {
                    let q1 = _mm512_hexl_mulhi_epi_64(v_inv_n_prime, x_plus_y_mod2q);
                    // X = inv_N * X_plus_Y_mod2q - Q1 * modulus;
                    let inv_n_tx = _mm512_hexl_mullo_epi_64(v_inv_n, x_plus_y_mod2q);
                    v_x = _mm512_hexl_mullo_add_lo_epi_64(inv_n_tx, q1, v_neg_modulus);

                    let q2 = _mm512_hexl_mulhi_epi_64(v_inv_n_w_prime, t);
                    // Y = inv_N_W * T - Q2 * modulus;
                    let inv_n_w_t = _mm512_hexl_mullo_epi_64(v_inv_n_w, t);
                    v_y = _mm512_hexl_mullo_add_lo_epi_64(inv_n_w_t, q2, v_neg_modulus);
                } else {
                    debug_assert!(false);
                }

                if output_mod_factor == 1 {
                    // Modulus reduction from [0, 2q), to [0, q)
                    v_x = _mm512_hexl_small_mod_epu64_2(v_x, v_modulus);
                    v_y = _mm512_hexl_small_mod_epu64_2(v_y, v_modulus);
                }

                _mm512_storeu_si512(x_chunk.as_mut_ptr().cast(), v_x);
                _mm512_storeu_si512(y_chunk.as_mut_ptr().cast(), v_y);
            }
        }
    }
}

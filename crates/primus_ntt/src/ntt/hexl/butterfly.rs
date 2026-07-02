use core::arch::x86_64::*;

use super::utils::*;

/// The Harvey butterfly: assume `X`, `Y` in `[0, 4q)`, and return `X'`, `Y'` in
/// `[0, 4q)` such that
/// `X' = X + W*Y (mod q)`, `Y' = X - W*Y (mod q)`.
///
/// See Algorithm 4 of <https://arxiv.org/pdf/1205.2926.pdf>
pub unsafe fn fwd_butterfly<const BIT_SHIFT: u32, const INPUT_LESS_THAN_MOD: bool>(
    x: &mut __m512i,
    y: &mut __m512i,
    w: __m512i,
    w_precon: __m512i,
    neg_modulus: __m512i,
    twice_modulus: __m512i,
) {
    if !INPUT_LESS_THAN_MOD {
        *x = unsafe { _mm512_hexl_small_mod_epu64_2(*x, twice_modulus) };
    }

    let mut t: __m512i;
    if BIT_SHIFT == 32 {
        unsafe {
            let mut q = _mm512_hexl_mullo_epi_64(w_precon, *y);
            q = _mm512_srli_epi64::<32>(q);
            let w_y = _mm512_hexl_mullo_epi_64(w, *y);
            t = _mm512_hexl_mullo_add_lo_epi_64(w_y, q, neg_modulus);
        }
    } else if BIT_SHIFT == 52 {
        unsafe {
            let q = _mm512_hexl_mulhi_epi_52(w_precon, *y);
            let w_y = _mm512_hexl_mullo_epi_52(w, *y);
            t = _mm512_hexl_mullo_add_lo_epi_52(w_y, q, neg_modulus);
        }
    } else if BIT_SHIFT == 64 {
        // Perform approximate computation of Q, as described in page 7 of
        // https://arxiv.org/pdf/2003.04510.pdf
        unsafe {
            let q = _mm512_hexl_mulhi_approx_epi_64(w_precon, *y);
            let w_y = _mm512_hexl_mullo_epi_64(w, *y);
            // Compute T in range [0, 4q)
            t = _mm512_hexl_mullo_add_lo_epi_64(w_y, q, neg_modulus);
            // Reduce T to range [0, 2q)
            t = _mm512_hexl_small_mod_epu64_2(t, twice_modulus);
        }
    } else {
        panic!("Invalid BitShift {BIT_SHIFT}");
    }

    unsafe {
        let twice_mod_minus_t = _mm512_sub_epi64(twice_modulus, t);
        *y = _mm512_add_epi64(*x, twice_mod_minus_t);
        *x = _mm512_add_epi64(*x, t);
    }
}

/// The Harvey butterfly: assume `X`, `Y` in `[0, 2q)`, and return `X'`, `Y'` in
/// `[0, 2q)` such that
/// `X' = X + Y (mod q)`, `Y' = W * (X - Y) (mod q)`.
///
/// See Algorithm 3 of <https://arxiv.org/pdf/1205.2926.pdf>
pub unsafe fn inv_butterfly<const BIT_SHIFT: u32, const INPUT_LESS_THAN_MOD: bool>(
    x: &mut __m512i,
    y: &mut __m512i,
    w: __m512i,
    w_precon: __m512i,
    neg_modulus: __m512i,
    twice_modulus: __m512i,
) {
    // Compute T first to allow in-place update of X
    let y_minus_2q = unsafe { _mm512_sub_epi64(*y, twice_modulus) };
    let t = unsafe { _mm512_sub_epi64(*x, y_minus_2q) };

    if INPUT_LESS_THAN_MOD {
        // No need for modulus reduction, since inputs are in [0, q)
        *x = unsafe { _mm512_add_epi64(*x, *y) };
    } else {
        // Algorithm 3 computes (X >= 2q) ? (X - 2q) : X
        // We instead compute (X - 2q >= 0) ? (X - 2q) : X
        // This allows us to use the faster _mm512_movepi64_mask rather than
        // _mm512_cmp_epu64_mask to create the mask.
        unsafe {
            *x = _mm512_add_epi64(*x, y_minus_2q);
            let sign_bits = _mm512_movepi64_mask(*x);
            *x = _mm512_mask_add_epi64(*x, sign_bits, *x, twice_modulus);
        }
    }

    if BIT_SHIFT == 32 {
        unsafe {
            let mut q = _mm512_hexl_mullo_epi_64(w_precon, t);
            q = _mm512_srli_epi64(q, 32);
            let q_p = _mm512_hexl_mullo_epi_64(q, neg_modulus);
            *y = _mm512_hexl_mullo_add_lo_epi_64(q_p, w, t);
        }
    } else if BIT_SHIFT == 52 {
        unsafe {
            let q = _mm512_hexl_mulhi_epi_52(w_precon, t);
            let q_p = _mm512_hexl_mullo_epi_52(q, neg_modulus);
            *y = _mm512_hexl_mullo_add_lo_epi_52(q_p, w, t);
        }
    } else if BIT_SHIFT == 64 {
        unsafe {
            // Perform approximate computation of Q, as described in page 7 of
            // https://arxiv.org/pdf/2003.04510.pdf
            let q = _mm512_hexl_mulhi_approx_epi_64(w_precon, t);
            let q_p = _mm512_hexl_mullo_epi_64(q, neg_modulus);
            // Compute Y in range [0, 4q)
            *y = _mm512_hexl_mullo_add_lo_epi_64(q_p, w, t);
            // Reduce Y to range [0, 2q)
            *y = _mm512_hexl_small_mod_epu64_2(*y, twice_modulus);
        }
    } else {
        debug_assert!(false, "Invalid BitShift {BIT_SHIFT}")
    }
}

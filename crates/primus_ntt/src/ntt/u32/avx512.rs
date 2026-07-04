//! AVX-512 accelerated forward and inverse NTT transforms for u32.
//!
//! Uses 512-bit vectors (16 × u32 lanes):
//! - T16 (t ≥ 16): broadcast W, contiguous x/y loads.
//! - T8  (t = 8): `permutex2var_epi32` deinterleave.
//! - T4 / T2 / T1: `permutex2var_epi32` deinterleave (4/8/16 blocks per group).
//!
//! Requires `n ≥ 64` — polynomial lengths below that are handled by the
//! scalar backend directly.
//!
//! # Safety
//!
//! All functions use `#[target_feature(enable = "avx512f")]` and are only
//! called after the public entry points verify runtime AVX-512 support via
//! [`HAS_AVX512F`].

use core::arch::x86_64::*;

use super::scalar;

/// Re-export from `crate::ntt::constants` so existing paths keep working.
pub use super::super::constants::HAS_AVX512F;

// ---------------------------------------------------------------------------
// Reduction helpers
// ---------------------------------------------------------------------------

/// `x mod bound` for `x < 2*bound` on 16 u32 lanes.
///
/// Uses `_mm512_min_epu32` — native in AVX-512F, unlike AVX2 where
/// `_mm256_min_epu32` was the widest unsigned min available.
#[target_feature(enable = "avx512f")]
#[inline]
fn reduce_once_avx512(x: __m512i, bound: __m512i) -> __m512i {
    _mm512_min_epu32(x, _mm512_sub_epi32(x, bound))
}

/// `x mod q` for `x < 4*q` on 16 u32 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx512f")]
#[inline]
fn reduce_twice_avx512(x: __m512i, q: __m512i, two_q: __m512i) -> __m512i {
    let x = reduce_once_avx512(x, two_q);
    reduce_once_avx512(x, q)
}

// ---------------------------------------------------------------------------
// T8 (t=8) load / store
// ---------------------------------------------------------------------------

/// Permutation mask for loading T8 x-values.
///
/// `_mm512_permutex2var_epi32` selector encoding:
/// - bit 4 = 0 → source from a, bit 4 = 1 → source from b
/// - bits[3:0] = lane index within the selected source
const PERM_T8_X: [i32; 16] = [
    // lanes 0..7: a lanes 0..7 (x values from block A)
    0, 1, 2, 3, 4, 5, 6, 7, // lanes 8..15: b lanes 0..7 (x values from block B)
    16, 17, 18, 19, 20, 21, 22, 23,
];

const PERM_T8_Y: [i32; 16] = [
    // lanes 0..7: a lanes 8..15 (y values from block A)
    8, 9, 10, 11, 12, 13, 14, 15, // lanes 8..15: b lanes 8..15 (y values from block B)
    24, 25, 26, 27, 28, 29, 30, 31,
];

/// Permutation mask for storing T8: reverse of load.
/// v_a = [x0..x7 from v_x | y0..y7 from v_y]
const PERM_T8_A: [i32; 16] = [
    // lanes 0..7: v_x lanes 0..7 → a lanes 0..7
    0, 1, 2, 3, 4, 5, 6, 7, // lanes 8..15: v_y lanes 0..7 → a lanes 8..15
    16, 17, 18, 19, 20, 21, 22, 23,
];

/// v_b = [x8..x15 from v_x | y8..y15 from v_y]
const PERM_T8_B: [i32; 16] = [
    // lanes 0..7: v_x lanes 8..15 → b lanes 0..7
    8, 9, 10, 11, 12, 13, 14, 15, // lanes 8..15: v_y lanes 8..15 → b lanes 8..15
    24, 25, 26, 27, 28, 29, 30, 31,
];

/// Load 2 T8 blocks (32 u32) and deinterleave into x and y vectors.
///
/// T8 layout: each block is `[x₀..x₇ | y₀..y₇]` (16 u32 = 512 bits).
/// Two consecutive blocks A, B produce:
///
/// ```text
/// v_x = [x_A0..x_A7 | x_B0..x_B7]    (all 16 x's)
/// v_y = [y_A0..y_A7 | y_B0..y_B7]    (all 16 y's)
/// ```
///
/// W vector must be `[W_B × 8 | W_A × 8]`.
#[target_feature(enable = "avx512f")]
#[inline]
fn t8_load_xy(ptr: *const __m512i) -> (__m512i, __m512i) {
    // SAFETY: caller ensures ptr points to 2 consecutive __m512i.
    let v_a = unsafe { _mm512_loadu_si512(ptr) };
    let v_b = unsafe { _mm512_loadu_si512(ptr.add(1)) };

    let idx_x = unsafe { _mm512_loadu_si512(PERM_T8_X.as_ptr().cast::<__m512i>()) };
    let idx_y = unsafe { _mm512_loadu_si512(PERM_T8_Y.as_ptr().cast::<__m512i>()) };

    let v_x = _mm512_permutex2var_epi32(v_a, idx_x, v_b);
    let v_y = _mm512_permutex2var_epi32(v_a, idx_y, v_b);
    (v_x, v_y)
}

/// Re-interleave x/y vectors back into two T8 blocks and store.
#[target_feature(enable = "avx512f")]
#[inline]
fn t8_store_xy(v_x: __m512i, v_y: __m512i, ptr: *mut __m512i) {
    let idx_a = unsafe { _mm512_loadu_si512(PERM_T8_A.as_ptr().cast::<__m512i>()) };
    let idx_b = unsafe { _mm512_loadu_si512(PERM_T8_B.as_ptr().cast::<__m512i>()) };

    let v_a = _mm512_permutex2var_epi32(v_x, idx_a, v_y);
    let v_b = _mm512_permutex2var_epi32(v_x, idx_b, v_y);

    // SAFETY: caller ensures ptr points to 2 writable __m512i.
    unsafe {
        _mm512_storeu_si512(ptr, v_a);
        _mm512_storeu_si512(ptr.add(1), v_b);
    }
}

// ---------------------------------------------------------------------------
// Barrett-32 lazy multiply for 16 u32 lanes
// ---------------------------------------------------------------------------

/// Barrett-32 lazy multiply for 16 u32 lanes.
///
/// Same even/odd split as the AVX2 version, widened to 512 bits.
///
/// `_mm512_mul_epu32` only multiplies the even-indexed u32 lanes
/// (0,2,4,…,14).  We handle odd lanes (1,3,…,15) by shifting them into
/// the even positions, multiplying, then shifting back.
#[target_feature(enable = "avx512f")]
#[inline]
fn mul_mod_lazy_avx512(y: __m512i, w: __m512i, wp: __m512i, q: __m512i) -> __m512i {
    // ---- Step 1: qhat = hi32(y * wp) ----
    //
    // Even lanes (0,2,4,…,14)
    let prod_wp_even = _mm512_mul_epu32(y, wp);
    let qhat_even = _mm512_srli_epi64::<32>(prod_wp_even);

    // Odd lanes (1,3,5,…,15)
    let y_shifted = _mm512_srli_epi64::<32>(y);
    let wp_shifted = _mm512_srli_epi64::<32>(wp);
    let prod_wp_odd = _mm512_mul_epu32(y_shifted, wp_shifted);
    let qhat_odd = _mm512_srli_epi64::<32>(prod_wp_odd);
    let qhat_odd = _mm512_slli_epi64::<32>(qhat_odd);

    // Interleave even/odd into 16 × u32.
    let qhat = _mm512_or_si512(qhat_even, qhat_odd);

    // ---- Step 2: t = low32(w*y) - low32(q*qhat) ----
    let wy = _mm512_mullo_epi32(w, y);
    let q_qhat = _mm512_mullo_epi32(q, qhat);
    _mm512_sub_epi32(wy, q_qhat)
}

// ---------------------------------------------------------------------------
// Butterflies
// ---------------------------------------------------------------------------

/// Forward Harvey butterfly on 16 u32 lanes.
#[target_feature(enable = "avx512f")]
#[inline]
fn fwd_butterfly_avx512(
    x: __m512i,
    y: __m512i,
    w: __m512i,
    wp: __m512i,
    q: __m512i,
    two_q: __m512i,
) -> (__m512i, __m512i) {
    let x0 = reduce_once_avx512(x, two_q);
    let t = mul_mod_lazy_avx512(y, w, wp, q);
    let x_new = _mm512_add_epi32(x0, t);
    let y_new = _mm512_sub_epi32(_mm512_add_epi32(x0, two_q), t);
    (x_new, y_new)
}

/// Inverse Harvey butterfly on 16 u32 lanes.
#[target_feature(enable = "avx512f")]
#[inline]
fn inv_butterfly_avx512(
    x: __m512i,
    y: __m512i,
    w: __m512i,
    wp: __m512i,
    q: __m512i,
    two_q: __m512i,
) -> (__m512i, __m512i) {
    let s = _mm512_add_epi32(x, y);
    let d = _mm512_sub_epi32(_mm512_add_epi32(x, two_q), y);
    let x_new = reduce_once_avx512(s, two_q);
    let y_new = mul_mod_lazy_avx512(d, w, wp, q);
    (x_new, y_new)
}

// ---------------------------------------------------------------------------
// T4 (t=4): 4-block deinterleave — 4 blocks → 2 × __m512i
// ---------------------------------------------------------------------------
//
// Each block is [x₀..x₃ | y₀..y₃] (8 u32).  Process 4 blocks A,B,C,D:
//   v0 = [xA..xA₃, yA₀..yA₃ | xB₀..xB₃, yB₀..yB₃]
//   v1 = [xC..xC₃, yC₀..yC₃ | xD₀..xD₃, yD₀..yD₃]

#[rustfmt::skip]
const PERM_T4_X: [i32; 16] = [
    0,  1,  2,  3,    // xA₀..xA₃ ← a  0..3
    8,  9,  10, 11,   // xB₀..xB₃ ← a  8..11
    16, 17, 18, 19,   // xC₀..xC₃ ← b  0..3
    24, 25, 26, 27,   // xD₀..xD₃ ← b  8..11
];

#[rustfmt::skip]
const PERM_T4_Y: [i32; 16] = [
    4,  5,  6,  7,    // yA₀..yA₃ ← a  4..7
    12, 13, 14, 15,   // yB₀..yB₃ ← a 12..15
    20, 21, 22, 23,   // yC₀..yC₃ ← b  4..7
    28, 29, 30, 31,   // yD₀..yD₃ ← b 12..15
];

#[rustfmt::skip]
const PERM_T4_STORE_A: [i32; 16] = [
    0,  1,  2,  3,    // xA₀..xA₃ ← v_x  0..3
    16, 17, 18, 19,   // yA₀..yA₃ ← v_y  0..3
    4,  5,  6,  7,    // xB₀..xB₃ ← v_x  4..7
    20, 21, 22, 23,   // yB₀..yB₃ ← v_y  4..7
];

#[rustfmt::skip]
const PERM_T4_STORE_B: [i32; 16] = [
    8,  9,  10, 11,   // xC₀..xC₃ ← v_x  8..11
    24, 25, 26, 27,   // yC₀..yC₃ ← v_y  8..11
    12, 13, 14, 15,   // xD₀..xD₃ ← v_x 12..15
    28, 29, 30, 31,   // yD₀..yD₃ ← v_y 12..15
];

// ---------------------------------------------------------------------------
// T2 (t=2): 8-block deinterleave — 8 blocks → 2 × __m512i
// ---------------------------------------------------------------------------
//
// Each block is [x₀,x₁ | y₀,y₁] (4 u32).  Process 8 blocks A..H:
//   v0 = [xA₀,xA₁,yA₀,yA₁, xB₀,xB₁,yB₀,yB₁, xC₀,xC₁,yC₀,yC₁, xD₀,xD₁,yD₀,yD₁]
//   v1 = [xE₀,xE₁,yE₀,yE₁, … xH₀,xH₁,yH₀,yH₁]

#[rustfmt::skip]
const PERM_T2_X: [i32; 16] = [
    0,  1,              // xA₀,xA₁ ← a  0,1
    4,  5,              // xB₀,xB₁ ← a  4,5
    8,  9,              // xC₀,xC₁ ← a  8,9
    12, 13,             // xD₀,xD₁ ← a 12,13
    16, 17,             // xE₀,xE₁ ← b  0,1
    20, 21,             // xF₀,xF₁ ← b  4,5
    24, 25,             // xG₀,xG₁ ← b  8,9
    28, 29,             // xH₀,xH₁ ← b 12,13
];

#[rustfmt::skip]
const PERM_T2_Y: [i32; 16] = [
    2,  3,              // yA₀,yA₁ ← a  2,3
    6,  7,              // yB₀,yB₁ ← a  6,7
    10, 11,             // yC₀,yC₁ ← a 10,11
    14, 15,             // yD₀,yD₁ ← a 14,15
    18, 19,             // yE₀,yE₁ ← b  2,3
    22, 23,             // yF₀,yF₁ ← b  6,7
    26, 27,             // yG₀,yG₁ ← b 10,11
    30, 31,             // yH₀,yH₁ ← b 14,15
];

#[rustfmt::skip]
const PERM_T2_STORE_A: [i32; 16] = [
    0,  1,              // xA₀,xA₁ ← v_x  0,1
    16, 17,             // yA₀,yA₁ ← v_y  0,1
    2,  3,              // xB₀,xB₁ ← v_x  2,3
    18, 19,             // yB₀,yB₁ ← v_y  2,3
    4,  5,              // xC₀,xC₁ ← v_x  4,5
    20, 21,             // yC₀,yC₁ ← v_y  4,5
    6,  7,              // xD₀,xD₁ ← v_x  6,7
    22, 23,             // yD₀,yD₁ ← v_y  6,7
];

#[rustfmt::skip]
const PERM_T2_STORE_B: [i32; 16] = [
    8,  9,              // xE₀,xE₁ ← v_x  8,9
    24, 25,             // yE₀,yE₁ ← v_y  8,9
    10, 11,             // xF₀,xF₁ ← v_x 10,11
    26, 27,             // yF₀,yF₁ ← v_y 10,11
    12, 13,             // xG₀,xG₁ ← v_x 12,13
    28, 29,             // yG₀,yG₁ ← v_y 12,13
    14, 15,             // xH₀,xH₁ ← v_x 14,15
    30, 31,             // yH₀,yH₁ ← v_y 14,15
];

// ---------------------------------------------------------------------------
// T1 (t=1): 16-block deinterleave — 16 blocks → 2 × __m512i
// ---------------------------------------------------------------------------
//
// Each block is [x | y] (2 u32).  Process 16 blocks A..P:
//   v0 = [xA,yA, xB,yB, … xH,yH]
//   v1 = [xI,yI, xJ,yJ, … xP,yP]

#[rustfmt::skip]
const PERM_T1_X: [i32; 16] = [
    0,  2,  4,  6,  8,  10, 12, 14,  // xA..xH ← a even lanes
    16, 18, 20, 22, 24, 26, 28, 30,  // xI..xP ← b even lanes
];

#[rustfmt::skip]
const PERM_T1_Y: [i32; 16] = [
    1,  3,  5,  7,  9,  11, 13, 15,  // yA..yH ← a odd lanes
    17, 19, 21, 23, 25, 27, 29, 31,  // yI..yP ← b odd lanes
];

#[rustfmt::skip]
const PERM_T1_STORE_A: [i32; 16] = [
    0, 16,  1, 17,  2, 18,  3, 19,
    4, 20,  5, 21,  6, 22,  7, 23,
];

#[rustfmt::skip]
const PERM_T1_STORE_B: [i32; 16] = [
    8, 24,  9, 25, 10, 26, 11, 27,
    12, 28, 13, 29, 14, 30, 15, 31,
];

// ---------------------------------------------------------------------------
// W-vector expansion for deinterleave stages
// ---------------------------------------------------------------------------

/// Expand `num_w = 16/t` consecutive W values into a 16-lane vector,
/// duplicating each value `t` times to match the deinterleaved lane order.
#[target_feature(enable = "avx512f")]
#[inline]
fn expand_w_16(w_ptr: *const u32, t: usize) -> __m512i {
    // SAFETY: caller ensures w_ptr points to at least 16/t readable u32 values.
    unsafe {
        match t {
            4 => {
                let w0 = *w_ptr;
                let w1 = *w_ptr.add(1);
                let w2 = *w_ptr.add(2);
                let w3 = *w_ptr.add(3);
                _mm512_set_epi32(
                    w3 as i32, w3 as i32, w3 as i32, w3 as i32, w2 as i32, w2 as i32, w2 as i32,
                    w2 as i32, w1 as i32, w1 as i32, w1 as i32, w1 as i32, w0 as i32, w0 as i32,
                    w0 as i32, w0 as i32,
                )
            }
            2 => {
                let w0 = *w_ptr;
                let w1 = *w_ptr.add(1);
                let w2 = *w_ptr.add(2);
                let w3 = *w_ptr.add(3);
                let w4 = *w_ptr.add(4);
                let w5 = *w_ptr.add(5);
                let w6 = *w_ptr.add(6);
                let w7 = *w_ptr.add(7);
                _mm512_set_epi32(
                    w7 as i32, w7 as i32, w6 as i32, w6 as i32, w5 as i32, w5 as i32, w4 as i32,
                    w4 as i32, w3 as i32, w3 as i32, w2 as i32, w2 as i32, w1 as i32, w1 as i32,
                    w0 as i32, w0 as i32,
                )
            }
            1 => _mm512_loadu_si512(w_ptr.cast::<__m512i>()),
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Generic deinterleave helpers
// ---------------------------------------------------------------------------

/// Pre-loaded permutation masks for one deinterleave stage.
struct DeinterleaveMasks {
    idx_x: __m512i,
    idx_y: __m512i,
    idx_sa: __m512i,
    idx_sb: __m512i,
}

impl DeinterleaveMasks {
    #[target_feature(enable = "avx512f")]
    unsafe fn load(x: &[i32; 16], y: &[i32; 16], sa: &[i32; 16], sb: &[i32; 16]) -> Self {
        unsafe {
            Self {
                idx_x: _mm512_loadu_si512(x.as_ptr().cast()),
                idx_y: _mm512_loadu_si512(y.as_ptr().cast()),
                idx_sa: _mm512_loadu_si512(sa.as_ptr().cast()),
                idx_sb: _mm512_loadu_si512(sb.as_ptr().cast()),
            }
        }
    }

    fn for_t(t: usize) -> Self {
        unsafe {
            match t {
                4 => Self::load(&PERM_T4_X, &PERM_T4_Y, &PERM_T4_STORE_A, &PERM_T4_STORE_B),
                2 => Self::load(&PERM_T2_X, &PERM_T2_Y, &PERM_T2_STORE_A, &PERM_T2_STORE_B),
                1 => Self::load(&PERM_T1_X, &PERM_T1_Y, &PERM_T1_STORE_A, &PERM_T1_STORE_B),
                _ => unreachable!(),
            }
        }
    }
}

/// Load two `__m512i`, deinterleave, butterfly, re-interleave, store.
#[target_feature(enable = "avx512f")]
#[inline]
fn deinterleave_fwd_stage(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
    masks: &DeinterleaveMasks,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));
        let v_x = _mm512_permutex2var_epi32(v_a, masks.idx_x, v_b);
        let v_y = _mm512_permutex2var_epi32(v_a, masks.idx_y, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
        let a_out = _mm512_permutex2var_epi32(v_x, masks.idx_sa, v_y);
        let b_out = _mm512_permutex2var_epi32(v_x, masks.idx_sb, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
fn deinterleave_inv_stage(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
    masks: &DeinterleaveMasks,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));
        let v_x = _mm512_permutex2var_epi32(v_a, masks.idx_x, v_b);
        let v_y = _mm512_permutex2var_epi32(v_a, masks.idx_y, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
        let a_out = _mm512_permutex2var_epi32(v_x, masks.idx_sa, v_y);
        let b_out = _mm512_permutex2var_epi32(v_x, masks.idx_sb, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

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
#[allow(clippy::too_many_arguments)]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn forward_transform(
    values: &mut [u32],
    q: u32,
    two_q: u32,
    roots: &[u32],
    roots_precon: &[u32],
    input_mod_factor: u32,
    output_mod_factor: u32,
) {
    debug_assert!(values.len().is_power_of_two());
    let n = values.len();

    if n < 64 {
        return scalar::forward_transform(
            values,
            q,
            two_q,
            roots,
            roots_precon,
            input_mod_factor,
            output_mod_factor,
        );
    }

    debug_assert!(
        matches!(input_mod_factor, 1 | 2 | 4),
        "input_mod_factor must be 1, 2 or 4; got {input_mod_factor}"
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 4,
        "output_mod_factor must be 1 or 4; got {output_mod_factor}"
    );

    let v_q = _mm512_set1_epi32(q as i32);
    let v_two_q = _mm512_set1_epi32(two_q as i32);

    let mut ri = 1usize; // skip roots[0] = 1
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
                    let v_x = unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                    let v_y = unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };
                    let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    unsafe {
                        _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_x);
                        _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_y);
                    }
                }
            }
        } else if t == 8 {
            // --- AVX-512 T8 path: 2-block deinterleave ---
            let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
            for chunk in chunks {
                let w_a = unsafe { *roots.get_unchecked(ri) };
                let wp_a = unsafe { *roots_precon.get_unchecked(ri) };
                ri += 1;
                let w_b = unsafe { *roots.get_unchecked(ri) };
                let wp_b = unsafe { *roots_precon.get_unchecked(ri) };
                ri += 1;

                // W: [W_B × 8 | W_A × 8]
                let v_w = _mm512_set_epi32(
                    w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32,
                    w_b as i32, w_b as i32, w_a as i32, w_a as i32, w_a as i32, w_a as i32,
                    w_a as i32, w_a as i32, w_a as i32, w_a as i32,
                );
                let v_wp = _mm512_set_epi32(
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                );

                let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                let (v_x, v_y) = t8_load_xy(ptr);
                let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                t8_store_xy(v_x, v_y, ptr);
            }
        } else {
            // --- AVX-512 deinterleave: t ∈ {4, 2, 1}, 32 elements at a time ---
            let num_w = 16 / t;
            let masks = DeinterleaveMasks::for_t(t);

            let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
            for chunk in chunks {
                let v_w = unsafe { expand_w_16(roots.as_ptr().add(ri), t) };
                let v_wp = unsafe { expand_w_16(roots_precon.as_ptr().add(ri), t) };
                ri += num_w;

                let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                deinterleave_fwd_stage(ptr, v_w, v_wp, v_q, v_two_q, &masks);
            }
        }
        t >>= 1;
        m <<= 1;
    }

    // Final canonical reduction: [0, 4q) → [0, q)
    if output_mod_factor == 1 {
        let (chunks, remainder) = values.as_chunks_mut::<16>();
        for chunk in chunks {
            let v = unsafe { _mm512_loadu_si512(chunk.as_mut_ptr().cast::<__m512i>()) };
            let v = reduce_twice_avx512(v, v_q, v_two_q);
            unsafe { _mm512_storeu_si512(chunk.as_mut_ptr().cast::<__m512i>(), v) };
        }
        for x in remainder {
            *x = scalar::reduce_twice(*x, q, two_q);
        }
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
#[allow(clippy::too_many_arguments)]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn inverse_transform(
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
    debug_assert!(values.len().is_power_of_two());
    let n = values.len();

    if n < 64 {
        return scalar::inverse_transform(
            values,
            q,
            two_q,
            inv_n,
            inv_n_precon,
            inv_roots,
            inv_roots_precon,
            input_mod_factor,
            output_mod_factor,
        );
    }

    debug_assert!(
        input_mod_factor == 1 || input_mod_factor == 2,
        "input_mod_factor must be 1 or 2; got {input_mod_factor}"
    );
    debug_assert!(
        output_mod_factor == 1 || output_mod_factor == 2,
        "output_mod_factor must be 1 or 2; got {output_mod_factor}"
    );

    let v_q = _mm512_set1_epi32(q as i32);
    let v_two_q = _mm512_set1_epi32(two_q as i32);

    let mut ri = 1usize; // skip inv_roots[0] = 1
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
                    let v_x = unsafe { _mm512_loadu_si512(x_chunk.as_mut_ptr().cast::<__m512i>()) };
                    let v_y = unsafe { _mm512_loadu_si512(y_chunk.as_mut_ptr().cast::<__m512i>()) };
                    let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                    unsafe {
                        _mm512_storeu_si512(x_chunk.as_mut_ptr().cast::<__m512i>(), v_x);
                        _mm512_storeu_si512(y_chunk.as_mut_ptr().cast::<__m512i>(), v_y);
                    }
                }
            }
        } else if t == 8 {
            // --- AVX-512 T8 path: 2-block deinterleave ---
            let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
            for chunk in chunks {
                let w_a = unsafe { *inv_roots.get_unchecked(ri) };
                let wp_a = unsafe { *inv_roots_precon.get_unchecked(ri) };
                ri += 1;
                let w_b = unsafe { *inv_roots.get_unchecked(ri) };
                let wp_b = unsafe { *inv_roots_precon.get_unchecked(ri) };
                ri += 1;

                // W: [W_B × 8 | W_A × 8]
                let v_w = _mm512_set_epi32(
                    w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32,
                    w_b as i32, w_b as i32, w_a as i32, w_a as i32, w_a as i32, w_a as i32,
                    w_a as i32, w_a as i32, w_a as i32, w_a as i32,
                );
                let v_wp = _mm512_set_epi32(
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_b as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                    wp_a as i32,
                );

                let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                let (v_x, v_y) = t8_load_xy(ptr);
                let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                t8_store_xy(v_x, v_y, ptr);
            }
        } else {
            // --- AVX-512 deinterleave: t ∈ {4, 2, 1}, 32 elements at a time ---
            let num_w = 16 / t;
            let masks = DeinterleaveMasks::for_t(t);

            let chunks = unsafe { values.as_chunks_unchecked_mut::<32>() };
            for chunk in chunks {
                let v_w = unsafe { expand_w_16(inv_roots.as_ptr().add(ri), t) };
                let v_wp = unsafe { expand_w_16(inv_roots_precon.as_ptr().add(ri), t) };
                ri += num_w;

                let ptr = chunk.as_mut_ptr().cast::<__m512i>();
                deinterleave_inv_stage(ptr, v_w, v_wp, v_q, v_two_q, &masks);
            }
        }
        t <<= 1;
        m >>= 1;
    }

    // --- Final stage: fused with inv_n multiply ---
    let last_w = unsafe { *inv_roots.get_unchecked(ri) };

    let inv_n_w = scalar::reduce_once(scalar::mul_mod_lazy(last_w, inv_n, inv_n_precon, q), q);
    let inv_n_w_precon = (((inv_n_w as u64) << 32) / q as u64) as u32;

    if n >= 32 {
        // --- AVX-512 final stage: n/2 ≥ 16, process 16 pairs at a time ---
        let v_inv_n = _mm512_set1_epi32(inv_n as i32);
        let v_inv_n_w = _mm512_set1_epi32(inv_n_w as i32);
        let v_inv_n_precon = _mm512_set1_epi32(inv_n_precon as i32);
        let v_inv_n_w_precon = _mm512_set1_epi32(inv_n_w_precon as i32);

        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<16>() };
        let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<16>() };
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
    } else {
        // --- Scalar final stage for N < 32 ---
        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        for (x, y) in xs.iter_mut().zip(ys.iter_mut()) {
            let tx = scalar::reduce_once(x.wrapping_add(*y), two_q);
            let ty = x.wrapping_add(two_q).wrapping_sub(*y);
            *x = scalar::mul_mod_lazy(tx, inv_n, inv_n_precon, q);
            *y = scalar::mul_mod_lazy(ty, inv_n_w, inv_n_w_precon, q);
        }
    }

    // Final canonical reduction: [0, 2q) → [0, q)
    if output_mod_factor == 1 {
        let (chunks, remainder) = values.as_chunks_mut::<16>();
        for chunk in chunks {
            let v = unsafe { _mm512_loadu_si512(chunk.as_mut_ptr().cast::<__m512i>()) };
            let v = reduce_once_avx512(v, v_q);
            unsafe { _mm512_storeu_si512(chunk.as_mut_ptr().cast::<__m512i>(), v) };
        }
        for x in remainder {
            *x = scalar::reduce_once(*x, q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_factor::ShoupFactor;

    /// Verify T8 AVX-512 forward butterfly vs scalar on 2 blocks with known W.
    #[test]
    fn test_t8_butterfly_against_scalar() {
        if !*HAS_AVX512F {
            return;
        }
        let q: u32 = 132120577;
        let two_q = q << 1;

        // 2 blocks × [x0..x7, y0..y7]: 32 values
        let mut avx_buf = [
            1u32, 2, 3, 4, 5, 6, 7, 8, // block A x's
            101, 102, 103, 104, 105, 106, 107, 108, // block A y's
            11, 12, 13, 14, 15, 16, 17, 18, // block B x's
            201, 202, 203, 204, 205, 206, 207, 208, // block B y's
        ];
        let mut scalar_buf = avx_buf;

        let w_a: u32 = 1111;
        let wp_a = ShoupFactor::<u32>::quotient_for(w_a, q);
        let w_b: u32 = 2222;
        let wp_b = ShoupFactor::<u32>::quotient_for(w_b, q);

        // AVX-512
        unsafe {
            let (v_x, v_y) = t8_load_xy(avx_buf.as_ptr().cast::<__m512i>());
            let v_w = _mm512_set_epi32(
                w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_b as i32,
                w_b as i32, w_a as i32, w_a as i32, w_a as i32, w_a as i32, w_a as i32, w_a as i32,
                w_a as i32, w_a as i32,
            );
            let v_wp = _mm512_set_epi32(
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_b as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
                wp_a as i32,
            );
            let v_q = _mm512_set1_epi32(q as i32);
            let v_two_q = _mm512_set1_epi32(two_q as i32);
            let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
            t8_store_xy(v_x, v_y, avx_buf.as_mut_ptr().cast::<__m512i>());
        }

        // Scalar: block A (indices 0..15), block B (indices 16..31)
        for block_idx in 0..2 {
            let off = block_idx * 16;
            let w = if block_idx == 0 { w_a } else { w_b };
            let wp = if block_idx == 0 { wp_a } else { wp_b };
            for i in 0..8 {
                let (xs, ys) = scalar_buf[off..off + 16].split_at_mut(8);
                scalar::fwd_butterfly(&mut xs[i], &mut ys[i], w, wp, q, two_q);
            }
        }

        for i in 0..32 {
            assert_eq!(
                avx_buf[i], scalar_buf[i],
                "T8 butterfly mismatch at index {i}"
            );
        }
    }

    /// Verify T8 load-store round-trip.
    #[test]
    fn test_t8_load_store_roundtrip() {
        if !*HAS_AVX512F {
            return;
        }
        let original: [u32; 32] = core::array::from_fn(|i| (i * 10) as u32);
        unsafe {
            let mut buf = original;
            let (v_x, v_y) = t8_load_xy(buf.as_ptr().cast::<__m512i>());
            t8_store_xy(v_x, v_y, buf.as_mut_ptr().cast::<__m512i>());
            assert_eq!(buf, original, "T8 load-store roundtrip failed");
        }
    }

    /// Verify `mul_mod_lazy_avx512` matches scalar for 16 distinct values.
    #[test]
    fn test_mul_mod_lazy_avx512() {
        if !*HAS_AVX512F {
            return;
        }

        let q: u32 = 132120577;

        let ys: [u32; 16] = core::array::from_fn(|i| (100 * (i + 1)) as u32);
        let ws: [u32; 16] = core::array::from_fn(|i| (10 * (i + 1)) as u32);
        let wps: [u32; 16] = ws.map(|v| ShoupFactor::<u32>::quotient_for(v, q));

        unsafe {
            let v_y = _mm512_loadu_si512(ys.as_ptr().cast::<__m512i>());
            let v_w = _mm512_loadu_si512(ws.as_ptr().cast::<__m512i>());
            let v_wp = _mm512_loadu_si512(wps.as_ptr().cast::<__m512i>());
            let v_q = _mm512_set1_epi32(q as i32);

            let result = mul_mod_lazy_avx512(v_y, v_w, v_wp, v_q);

            let mut out = [0u32; 16];
            _mm512_storeu_si512(out.as_mut_ptr().cast::<__m512i>(), result);

            for i in 0..16 {
                let expected = scalar::mul_mod_lazy(ys[i], ws[i], wps[i], q);
                assert_eq!(out[i], expected, "lane {i}: y={} w={}", ys[i], ws[i]);
            }
        }
    }
}

//! AVX2-accelerated forward and inverse NTT transforms for u32.
//!
//! All stages (t ≥ 1) are vectorised using 256-bit vectors (8 × u32 lanes):
//! - T8 (t ≥ 8): broadcast W, contiguous x/y loads.
//! - T4 (t = 4): `permute2x128` deinterleave.
//! - T2 (t = 2): `unpacklo/hi_epi64` + `permute4x64` deinterleave.
//! - T1 (t = 1): `permutevar8x32` gather-like deinterleave.
//!
//! Requires `n ≥ 32` — polynomial lengths below that are handled by
//! the scalar backend directly.  This constraint also guarantees the
//! same `n ≥ 32` lower bound needed for future AVX-512 (16 lanes).
//!
//! # Safety
//!
//! All functions use `#[target_feature(enable = "avx2")]` and are only
//! called after the public entry points verify runtime AVX2 support via
//! [`HAS_AVX2`].  Internal helpers are safe `fn` (not `unsafe fn`)
//! because the `#[target_feature]` attribute ensures the right ISA is
//! available; only operations that dereference raw pointers or call
//! `_unchecked` slice methods need `unsafe {}` blocks.

use core::arch::x86_64::*;

use super::scalar;

/// Re-export from `crate::ntt::constants` so existing `avx2::HAS_AVX2`
/// paths keep working.
pub use super::super::constants::HAS_AVX2;

// ---------------------------------------------------------------------------
// Reduction helpers
// ---------------------------------------------------------------------------

/// `x mod bound` for `x < 2*bound` on 8 u32 lanes.
///
/// Uses `_mm256_min_epu32` to implement the same branchless unsigned-min
/// pattern as the scalar `x.min(x.wrapping_sub(bound))`: when `x < bound`,
/// `x - bound` wraps to a large unsigned value and `min` picks `x`;
/// when `x >= bound`, `min` picks `x - bound`.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_once_avx2(x: __m256i, bound: __m256i) -> __m256i {
    _mm256_min_epu32(x, _mm256_sub_epi32(x, bound))
}

/// `x mod q` for `x < 4*q` on 8 u32 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_twice_avx2(x: __m256i, q: __m256i, two_q: __m256i) -> __m256i {
    let x = reduce_once_avx2(x, two_q); // -> [0, 2q)
    reduce_once_avx2(x, q) // -> [0, q)
}

// ---------------------------------------------------------------------------
// T4 interleave helpers
// ---------------------------------------------------------------------------

/// Load x/y from two T4 blocks and deinterleave into dedicated x and y vectors.
///
/// T4 layout: each block is `[x₀..x₃ | y₀..y₃]` (8 × u32 = 256 bits).
/// Two consecutive blocks A, B produce:
///
/// ```text
/// v_x = [x₄..x₇ | x₀..x₃]    (B's xs in lanes 7..4, A's xs in lanes 3..0)
/// v_y = [y₄..y₇ | y₀..y₃]    (B's ys in lanes 7..4, A's ys in lanes 3..0)
/// ```
///
/// The corresponding W vector must therefore be
/// `[W_b × 4 | W_a × 4]` to match this lane order.
#[target_feature(enable = "avx2")]
#[inline]
fn t4_load_xy(block_a: *const __m256i, block_b: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures pointers are valid.
    let v_a = unsafe { _mm256_loadu_si256(block_a) };
    let v_b = unsafe { _mm256_loadu_si256(block_b) };
    let v_x = _mm256_permute2x128_si256::<0x20>(v_a, v_b);
    let v_y = _mm256_permute2x128_si256::<0x31>(v_a, v_b);
    (v_x, v_y)
}

/// Re-interleave x/y vectors back into two T4 blocks and store.
#[target_feature(enable = "avx2")]
#[inline]
fn t4_store_xy(v_x: __m256i, v_y: __m256i, block_a: *mut __m256i, block_b: *mut __m256i) {
    let v_a = _mm256_permute2x128_si256::<0x20>(v_x, v_y);
    let v_b = _mm256_permute2x128_si256::<0x31>(v_x, v_y);
    // SAFETY: caller ensures pointers are valid and writable.
    unsafe {
        _mm256_storeu_si256(block_a, v_a);
        _mm256_storeu_si256(block_b, v_b);
    }
}

// ---------------------------------------------------------------------------
// T2 (t=2) load / store
// ---------------------------------------------------------------------------

/// Load 4 T2 blocks (16 u32) and deinterleave into x and y vectors.
///
/// T2 layout: each block is `[x₀,x₁ | y₀,y₁]` (4 u32 = 128 bits).
/// Four consecutive blocks 0..3 produce:
///
/// ```text
/// v_x = [x₆,x₇,x₂,x₃, x₄,x₅,x₀,x₁]    (block3, block1, block2, block0)
/// v_y = [y₆,y₇,y₂,y₃, y₄,y₅,y₀,y₁]
/// ```
///
/// W vector must be `[W₃,W₃,W₁,W₁, W₂,W₂,W₀,W₀]` (lanes 7..0).
#[target_feature(enable = "avx2")]
#[inline]
fn t2_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures ptr points to 2 consecutive __m256i.
    let v0 = unsafe { _mm256_loadu_si256(ptr) };
    let v1 = unsafe { _mm256_loadu_si256(ptr.add(1)) };
    let v_x = _mm256_unpacklo_epi64(v0, v1);
    let v_y = _mm256_unpackhi_epi64(v0, v1);
    (v_x, v_y)
}

#[target_feature(enable = "avx2")]
#[inline]
fn t2_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
    // Reconstruct: v0 = [block1 | block0], v1 = [block3 | block2]
    // v_x lane 0 = block0 xs, lane 2 = block1 xs → x_lo lanes [2:2:0:0]
    let x_lo = _mm256_permute4x64_epi64::<0x28>(v_x); // 0b00_10_10_00
    let y_lo = _mm256_permute4x64_epi64::<0x28>(v_y);
    let v0 = _mm256_unpacklo_epi64(x_lo, y_lo);

    // v_x lane 1 = block2 xs, lane 3 = block3 xs → x_hi lanes [3:3:1:1]
    let x_hi = _mm256_permute4x64_epi64::<0xFD>(v_x); // 0b11_11_11_01
    let y_hi = _mm256_permute4x64_epi64::<0xFD>(v_y);
    let v1 = _mm256_unpacklo_epi64(x_hi, y_hi);

    // SAFETY: caller ensures ptr points to 2 writable __m256i.
    unsafe {
        _mm256_storeu_si256(ptr, v0);
        _mm256_storeu_si256(ptr.add(1), v1);
    }
}

// ---------------------------------------------------------------------------
// T1 (t=1) load / store
// ---------------------------------------------------------------------------

/// Load 8 T1 blocks (16 u32) and deinterleave into x and y vectors.
///
/// T1 layout: each block is `[x | y]` (2 u32 = 64 bits).
/// Eight consecutive blocks 0..7 produce:
///
/// ```text
/// v_x = [x₇,x₆,x₅,x₄, x₃,x₂,x₁,x₀]    (block 7..0 in lanes 7..0)
/// v_y = [y₇,y₆,y₅,y₄, y₃,y₂,y₁,y₀]
/// ```
///
/// W vector is `[W₇,W₆,W₅,W₄, W₃,W₂,W₁,W₀]` — same lane order.
#[target_feature(enable = "avx2")]
#[inline]
fn t1_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
    // Select even positions (0,2,4,6) from each 128‑bit half
    let idx_x = _mm256_set_epi32(6, 4, 6, 4, 6, 4, 2, 0);
    // Select odd positions (1,3,5,7)
    let idx_y = _mm256_set_epi32(7, 5, 7, 5, 7, 5, 3, 1);

    // SAFETY: caller ensures ptr points to 2 consecutive __m256i.
    let v0 = unsafe { _mm256_loadu_si256(ptr) };
    let v1 = unsafe { _mm256_loadu_si256(ptr.add(1)) };

    let v0_x = _mm256_permutevar8x32_epi32(v0, idx_x);
    let v1_x = _mm256_permutevar8x32_epi32(v1, idx_x);
    let v0_y = _mm256_permutevar8x32_epi32(v0, idx_y);
    let v1_y = _mm256_permutevar8x32_epi32(v1, idx_y);

    let v_x = _mm256_insertf128_si256(v0_x, _mm256_castsi256_si128(v1_x), 1);
    let v_y = _mm256_insertf128_si256(v0_y, _mm256_castsi256_si128(v1_y), 1);
    (v_x, v_y)
}

#[target_feature(enable = "avx2")]
#[inline]
fn t1_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
    let temp0 = _mm256_unpacklo_epi32(v_x, v_y);
    let temp1 = _mm256_unpackhi_epi32(v_x, v_y);

    let v0 = _mm256_insertf128_si256(
        _mm256_castsi128_si256(_mm256_extractf128_si256::<0>(temp0)),
        _mm256_extractf128_si256::<0>(temp1),
        1,
    );
    let v1 = _mm256_insertf128_si256(
        _mm256_castsi128_si256(_mm256_extractf128_si256::<1>(temp0)),
        _mm256_extractf128_si256::<1>(temp1),
        1,
    );

    // SAFETY: caller ensures ptr points to 2 writable __m256i.
    unsafe {
        _mm256_storeu_si256(ptr, v0);
        _mm256_storeu_si256(ptr.add(1), v1);
    }
}

/// Barrett-32 lazy multiply for 8 u32 lanes.
///
/// Computes `qhat = (y * wp) >> 32` then `t = w*y - q*qhat` (all modulo 2³²).
/// Each result is in `[0, 2q)` by the Harvey/Barrett bound (requires `q < 2³⁰`).
///
/// # Implementation note
///
/// AVX2 lacks a full 8-lane `u32 × u32 → u64` multiply. `_mm256_mul_epu32`
/// only multiplies the even-indexed u32 lanes within each 64-bit element.
/// We therefore split the work into even lanes (0, 2, 4, 6) and odd lanes
/// (1, 3, 5, 7), then interleave the results.
#[target_feature(enable = "avx2")]
#[inline]
fn mul_mod_lazy_avx2(y: __m256i, w: __m256i, wp: __m256i, q: __m256i) -> __m256i {
    // ---- Step 1: qhat = hi32(y * wp) ----
    //
    // Even lanes (0,2,4,6) — _mm256_mul_epu32 naturally picks them up.
    let prod_wp_even = _mm256_mul_epu32(y, wp);
    // After srli_epi64::<32>, each 64-bit lane's high 32 bits are already
    // zero — no mask needed.
    let qhat_even = _mm256_srli_epi64::<32>(prod_wp_even);

    // Odd lanes (1,3,5,7): shift both y and wp so their odd-positioned
    // values move to the even positions that _mm256_mul_epu32 reads from.
    let y_shifted = _mm256_srli_epi64::<32>(y);
    let wp_shifted = _mm256_srli_epi64::<32>(wp);
    let prod_wp_odd = _mm256_mul_epu32(y_shifted, wp_shifted);
    let qhat_odd = _mm256_srli_epi64::<32>(prod_wp_odd);
    // Move the odd qhat values to the upper 32 bits of each 64-bit lane,
    // where the odd u32 lanes live in the 256-bit register.
    let qhat_odd = _mm256_slli_epi64::<32>(qhat_odd);

    // Interleave even and odd qhat into one vector of 8 × u32.
    let qhat = _mm256_or_si256(qhat_even, qhat_odd);

    // ---- Step 2: t = low32(w*y) - low32(q*qhat) ----
    let wy = _mm256_mullo_epi32(w, y);
    let q_qhat = _mm256_mullo_epi32(q, qhat);
    _mm256_sub_epi32(wy, q_qhat)
}

// ---------------------------------------------------------------------------
// Butterflies
// ---------------------------------------------------------------------------

/// Forward Harvey butterfly on 8 u32 lanes.
///
/// Input:  `x`, `y` each in `[0, 4q)`.
/// Output: `x'`, `y'` each in `[0, 4q)`.
///
/// Algorithm:
/// ```text
/// x0 = reduce_once(x, two_q)
/// t  = mul_mod_lazy(y, w, wp, q)
/// x' = x0 + t
/// y' = x0 + two_q - t
/// ```
#[target_feature(enable = "avx2")]
#[inline]
fn fwd_butterfly_avx2(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let x0 = reduce_once_avx2(x, two_q);
    let t = mul_mod_lazy_avx2(y, w, wp, q);
    let x_new = _mm256_add_epi32(x0, t);
    let y_new = _mm256_sub_epi32(_mm256_add_epi32(x0, two_q), t);
    (x_new, y_new)
}

/// Inverse Harvey butterfly on 8 u32 lanes.
///
/// Input:  `x`, `y` each in `[0, 2q)`.
/// Output: `x'`, `y'` each in `[0, 2q)`.
///
/// Algorithm:
/// ```text
/// s  = x + y
/// d  = x + two_q - y
/// x' = reduce_once(s, two_q)
/// y' = mul_mod_lazy(d, w, wp, q)
/// ```
#[target_feature(enable = "avx2")]
#[inline]
fn inv_butterfly_avx2(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let s = _mm256_add_epi32(x, y);
    let d = _mm256_sub_epi32(_mm256_add_epi32(x, two_q), y);
    let x_new = reduce_once_avx2(s, two_q);
    let y_new = mul_mod_lazy_avx2(d, w, wp, q);
    (x_new, y_new)
}

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
#[allow(clippy::too_many_arguments)]
#[target_feature(enable = "avx2")]
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

    // Polynomial lengths below 32 are trivial — delegate to scalar.
    if n < 32 {
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

    let v_q = _mm256_set1_epi32(q as i32);
    let v_two_q = _mm256_set1_epi32(two_q as i32);

    let mut ri = 1usize; // skip roots[0] = 1
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
                    let v_x = unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                    let v_y = unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
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
                        let w_a = unsafe { *roots.get_unchecked(ri) };
                        let wp_a = unsafe { *roots_precon.get_unchecked(ri) };
                        ri += 1;
                        let w_b = unsafe { *roots.get_unchecked(ri) };
                        let wp_b = unsafe { *roots_precon.get_unchecked(ri) };
                        ri += 1;

                        let v_w = _mm256_set_epi32(
                            w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_a as i32, w_a as i32,
                            w_a as i32, w_a as i32,
                        );
                        let v_wp = _mm256_set_epi32(
                            wp_b as i32,
                            wp_b as i32,
                            wp_b as i32,
                            wp_b as i32,
                            wp_a as i32,
                            wp_a as i32,
                            wp_a as i32,
                            wp_a as i32,
                        );

                        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                        let (v_x, v_y) = t4_load_xy(ptr, unsafe { ptr.add(1) });
                        let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        t4_store_xy(v_x, v_y, ptr, unsafe { ptr.add(1) });
                    }
                }
                2 => {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                    for chunk in chunks {
                        let w0 = unsafe { *roots.get_unchecked(ri) };
                        let wp0 = unsafe { *roots_precon.get_unchecked(ri) };
                        let w1 = unsafe { *roots.get_unchecked(ri + 1) };
                        let wp1 = unsafe { *roots_precon.get_unchecked(ri + 1) };
                        let w2 = unsafe { *roots.get_unchecked(ri + 2) };
                        let wp2 = unsafe { *roots_precon.get_unchecked(ri + 2) };
                        let w3 = unsafe { *roots.get_unchecked(ri + 3) };
                        let wp3 = unsafe { *roots_precon.get_unchecked(ri + 3) };
                        ri += 4;
                        let v_w = _mm256_set_epi32(
                            w3 as i32, w3 as i32, w1 as i32, w1 as i32, w2 as i32, w2 as i32,
                            w0 as i32, w0 as i32,
                        );
                        let v_wp = _mm256_set_epi32(
                            wp3 as i32, wp3 as i32, wp1 as i32, wp1 as i32, wp2 as i32, wp2 as i32,
                            wp0 as i32, wp0 as i32,
                        );
                        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                        let (v_x, v_y) = t2_load_xy(ptr);
                        let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        t2_store_xy(v_x, v_y, ptr);
                    }
                }
                1 => {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                    for chunk in chunks {
                        let v_w =
                            unsafe { _mm256_loadu_si256(roots.as_ptr().add(ri).cast::<__m256i>()) };
                        let v_wp = unsafe {
                            _mm256_loadu_si256(roots_precon.as_ptr().add(ri).cast::<__m256i>())
                        };
                        ri += 8;
                        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                        let (v_x, v_y) = t1_load_xy(ptr);
                        let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        t1_store_xy(v_x, v_y, ptr);
                    }
                }
                _ => unreachable!("t < 8 and t is a power of two => t ∈ {{1, 2, 4}}"),
            }
        }
        t >>= 1;
        m <<= 1;
    }

    // Final canonical reduction: [0, 4q) → [0, q)
    if output_mod_factor == 1 {
        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
        for chunk in chunks {
            let v = unsafe { _mm256_loadu_si256(chunk.as_mut_ptr().cast::<__m256i>()) };
            let v = reduce_twice_avx2(v, v_q, v_two_q);
            unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast::<__m256i>(), v) };
        }
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
#[allow(clippy::too_many_arguments)]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn inverse_transform(
    values: &mut [u32],
    q: u32,
    two_q: u32,
    inv_n: u32,
    inv_n_precon: u32,
    inv_n_w: u32,
    inv_n_w_precon: u32,
    inv_roots: &[u32],
    inv_roots_precon: &[u32],
    input_mod_factor: u32,
    output_mod_factor: u32,
) {
    debug_assert!(values.len().is_power_of_two());
    let n = values.len();

    if n < 32 {
        return scalar::inverse_transform(
            values,
            q,
            two_q,
            inv_n,
            inv_n_precon,
            inv_n_w,
            inv_n_w_precon,
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

    let v_q = _mm256_set1_epi32(q as i32);
    let v_two_q = _mm256_set1_epi32(two_q as i32);

    let mut ri = 1usize; // skip inv_roots[0] = 1
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
                    let v_x = unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                    let v_y = unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
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
                            _mm256_loadu_si256(inv_roots.as_ptr().add(ri).cast::<__m256i>())
                        };
                        let v_wp = unsafe {
                            _mm256_loadu_si256(inv_roots_precon.as_ptr().add(ri).cast::<__m256i>())
                        };
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
                        let w0 = unsafe { *inv_roots.get_unchecked(ri) };
                        let wp0 = unsafe { *inv_roots_precon.get_unchecked(ri) };
                        let w1 = unsafe { *inv_roots.get_unchecked(ri + 1) };
                        let wp1 = unsafe { *inv_roots_precon.get_unchecked(ri + 1) };
                        let w2 = unsafe { *inv_roots.get_unchecked(ri + 2) };
                        let wp2 = unsafe { *inv_roots_precon.get_unchecked(ri + 2) };
                        let w3 = unsafe { *inv_roots.get_unchecked(ri + 3) };
                        let wp3 = unsafe { *inv_roots_precon.get_unchecked(ri + 3) };
                        ri += 4;
                        let v_w = _mm256_set_epi32(
                            w3 as i32, w3 as i32, w1 as i32, w1 as i32, w2 as i32, w2 as i32,
                            w0 as i32, w0 as i32,
                        );
                        let v_wp = _mm256_set_epi32(
                            wp3 as i32, wp3 as i32, wp1 as i32, wp1 as i32, wp2 as i32, wp2 as i32,
                            wp0 as i32, wp0 as i32,
                        );
                        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                        let (v_x, v_y) = t2_load_xy(ptr);
                        let (v_x, v_y) = inv_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        t2_store_xy(v_x, v_y, ptr);
                    }
                }
                4 => {
                    let chunks = unsafe { values.as_chunks_unchecked_mut::<16>() };
                    for chunk in chunks {
                        let w_a = unsafe { *inv_roots.get_unchecked(ri) };
                        let wp_a = unsafe { *inv_roots_precon.get_unchecked(ri) };
                        ri += 1;
                        let w_b = unsafe { *inv_roots.get_unchecked(ri) };
                        let wp_b = unsafe { *inv_roots_precon.get_unchecked(ri) };
                        ri += 1;

                        let v_w = _mm256_set_epi32(
                            w_b as i32, w_b as i32, w_b as i32, w_b as i32, w_a as i32, w_a as i32,
                            w_a as i32, w_a as i32,
                        );
                        let v_wp = _mm256_set_epi32(
                            wp_b as i32,
                            wp_b as i32,
                            wp_b as i32,
                            wp_b as i32,
                            wp_a as i32,
                            wp_a as i32,
                            wp_a as i32,
                            wp_a as i32,
                        );

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

    // Final canonical reduction: [0, 2q) → [0, q)
    if output_mod_factor == 1 {
        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
        for chunk in chunks {
            let v = unsafe { _mm256_loadu_si256(chunk.as_mut_ptr().cast::<__m256i>()) };
            let v = reduce_once_avx2(v, v_q);
            unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast::<__m256i>(), v) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_factor::ShoupFactor;

    /// Verify T2 AVX2 forward butterfly vs scalar on 4 blocks with known W.
    #[test]
    fn test_t2_butterfly_against_scalar() {
        if !*HAS_AVX2 {
            return;
        }
        let q: u32 = 132120577;
        let two_q = q << 1;

        // 4 blocks × [x0,x1,y0,y1]: 16 values
        let mut avx_buf = [
            10u32, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ];
        let mut scalar_buf = avx_buf;

        let ws = [1111u32, 2222, 3333, 4444];
        let wps = [
            ShoupFactor::<u32>::quotient_for(1111, q),
            ShoupFactor::<u32>::quotient_for(2222, q),
            ShoupFactor::<u32>::quotient_for(3333, q),
            ShoupFactor::<u32>::quotient_for(4444, q),
        ];

        // AVX2: load, butterfly, store
        unsafe {
            let (v_x, v_y) = t2_load_xy(avx_buf.as_ptr().cast::<__m256i>());
            let v_w = _mm256_set_epi32(
                ws[3] as i32,
                ws[3] as i32,
                ws[1] as i32,
                ws[1] as i32,
                ws[2] as i32,
                ws[2] as i32,
                ws[0] as i32,
                ws[0] as i32,
            );
            let v_wp = _mm256_set_epi32(
                wps[3] as i32,
                wps[3] as i32,
                wps[1] as i32,
                wps[1] as i32,
                wps[2] as i32,
                wps[2] as i32,
                wps[0] as i32,
                wps[0] as i32,
            );
            let v_q = _mm256_set1_epi32(q as i32);
            let v_two_q = _mm256_set1_epi32(two_q as i32);
            let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
            t2_store_xy(v_x, v_y, avx_buf.as_mut_ptr().cast::<__m256i>());
        }

        // Scalar: apply butterfly per block in order 0,1,2,3
        // (t2_store_xy restores blocks to original order)
        for block_idx in 0..4 {
            let i = block_idx * 4;
            let (x0, rest) = scalar_buf[i..].split_at_mut(1);
            let (x1, rest) = rest.split_at_mut(1);
            let (y0, rest) = rest.split_at_mut(1);
            let (y1, _) = rest.split_at_mut(1);
            scalar::fwd_butterfly(
                &mut x0[0],
                &mut y0[0],
                ws[block_idx],
                wps[block_idx],
                q,
                two_q,
            );
            scalar::fwd_butterfly(
                &mut x1[0],
                &mut y1[0],
                ws[block_idx],
                wps[block_idx],
                q,
                two_q,
            );
        }

        for i in 0..16 {
            assert_eq!(
                avx_buf[i], scalar_buf[i],
                "T2 butterfly mismatch at index {i}"
            );
        }
    }

    /// Verify T1 AVX2 forward butterfly vs scalar on 8 blocks with known W.
    #[test]
    fn test_t1_butterfly_against_scalar() {
        if !*HAS_AVX2 {
            return;
        }
        let q: u32 = 132120577;
        let two_q = q << 1;

        // 8 blocks × [x, y]: 16 values
        let mut avx_buf = [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut scalar_buf = avx_buf;

        let w_vals = [100u32, 200, 300, 400, 500, 600, 700, 800];
        let wp_vals: [u32; 8] = w_vals.map(|v| ShoupFactor::<u32>::quotient_for(v, q));

        // AVX2
        unsafe {
            let (v_x, v_y) = t1_load_xy(avx_buf.as_ptr().cast::<__m256i>());
            let v_w = _mm256_loadu_si256(w_vals.as_ptr().cast::<__m256i>());
            let v_wp = _mm256_loadu_si256(wp_vals.as_ptr().cast::<__m256i>());
            let v_q = _mm256_set1_epi32(q as i32);
            let v_two_q = _mm256_set1_epi32(two_q as i32);
            let (v_x, v_y) = fwd_butterfly_avx2(v_x, v_y, v_w, v_wp, v_q, v_two_q);
            t1_store_xy(v_x, v_y, avx_buf.as_mut_ptr().cast::<__m256i>());
        }

        // Scalar
        for block_idx in 0..8 {
            let (x, rest) = scalar_buf.split_at_mut(block_idx * 2 + 1);
            let (y, _) = rest.split_at_mut(1);
            scalar::fwd_butterfly(
                &mut x[block_idx * 2],
                &mut y[0],
                w_vals[block_idx],
                wp_vals[block_idx],
                q,
                two_q,
            );
        }

        for i in 0..16 {
            assert_eq!(
                avx_buf[i], scalar_buf[i],
                "T1 butterfly mismatch at index {i}"
            );
        }
    }

    /// Verify T2 load-store round-trip: reloaded data must match original.
    #[test]
    fn test_t2_load_store_roundtrip() {
        if !*HAS_AVX2 {
            return;
        }
        let original: [u32; 16] = [
            100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600,
        ];
        unsafe {
            let mut buf = original;
            let (v_x, v_y) = t2_load_xy(buf.as_ptr().cast::<__m256i>());
            t2_store_xy(v_x, v_y, buf.as_mut_ptr().cast::<__m256i>());
            assert_eq!(buf, original, "T2 load-store roundtrip failed");
        }
    }

    /// Verify T1 load-store round-trip.
    #[test]
    fn test_t1_load_store_roundtrip() {
        if !*HAS_AVX2 {
            return;
        }
        let original: [u32; 16] = [
            100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600,
        ];
        unsafe {
            let mut buf = original;
            let (v_x, v_y) = t1_load_xy(buf.as_ptr().cast::<__m256i>());
            t1_store_xy(v_x, v_y, buf.as_mut_ptr().cast::<__m256i>());
            assert_eq!(buf, original, "T1 load-store roundtrip failed");
        }
    }

    /// Verify that `mul_mod_lazy_avx2` matches scalar `mul_mod_lazy` for
    /// non-broadcast twiddle values, exercising the even/odd split.
    #[test]
    fn test_mul_mod_lazy_avx2() {
        if !*HAS_AVX2 {
            return;
        }

        let q: u32 = 132120577; // 27-bit prime

        // 8 distinct (y, w, wp) triples — non-broadcast, exercises both
        // even and odd lane paths.
        let ys = [100u32, 200, 300, 400, 500, 600, 700, 800];
        let ws = [10u32, 20, 30, 40, 50, 60, 70, 80];
        let wps: [u32; 8] = [
            ShoupFactor::<u32>::quotient_for(10, q),
            ShoupFactor::<u32>::quotient_for(20, q),
            ShoupFactor::<u32>::quotient_for(30, q),
            ShoupFactor::<u32>::quotient_for(40, q),
            ShoupFactor::<u32>::quotient_for(50, q),
            ShoupFactor::<u32>::quotient_for(60, q),
            ShoupFactor::<u32>::quotient_for(70, q),
            ShoupFactor::<u32>::quotient_for(80, q),
        ];

        unsafe {
            let v_y = _mm256_loadu_si256(ys.as_ptr().cast::<__m256i>());
            let v_w = _mm256_loadu_si256(ws.as_ptr().cast::<__m256i>());
            let v_wp = _mm256_loadu_si256(wps.as_ptr().cast::<__m256i>());
            let v_q = _mm256_set1_epi32(q as i32);

            let result = mul_mod_lazy_avx2(v_y, v_w, v_wp, v_q);

            let mut out = [0u32; 8];
            _mm256_storeu_si256(out.as_mut_ptr().cast::<__m256i>(), result);

            for i in 0..8 {
                let expected = scalar::mul_mod_lazy(ys[i], ws[i], wps[i], q);
                assert_eq!(
                    out[i], expected,
                    "lane {i}: y={} w={} wp={}",
                    ys[i], ws[i], wps[i]
                );
            }
        }
    }
}

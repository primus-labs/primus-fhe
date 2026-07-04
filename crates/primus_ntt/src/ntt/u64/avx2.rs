//! AVX2-accelerated forward and inverse NTT transforms for u64.
//!
//! Uses 256-bit vectors (4 × u64 lanes).  Because AVX2 lacks native packed
//! 64 × 64 → 128 multiplication, every widening multiply is implemented via
//! 32-bit decomposition (4 `_mm256_mul_epu32` cross-products + recombination,
//! adapted from <https://stackoverflow.com/a/28827013>).
//!
//! All stages (t ≥ 1) are vectorised:
//! - T4 (t ≥ 4): broadcast W, contiguous x/y loads.
//! - T2 (t = 2): `permute2x128` deinterleave.
//! - T1 (t = 1): `unpacklo/hi_epi64` + `permute4x64` deinterleave.
//!
//! Requires `n ≥ 16` — polynomial lengths below that are handled by the
//! scalar backend directly.
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

use super::U64NttTable;

// ---------------------------------------------------------------------------
// Reduction helpers
// ---------------------------------------------------------------------------

/// `x mod bound` for `x < 2*bound` on 4 u64 lanes.
///
/// AVX2 lacks `_mm256_min_epu64`, so we use the unsigned-to-signed compare
/// trick: XOR both operands with the MSB, then use signed `cmpgt`, then
/// blend.
///
/// Equivalent to scalar `x.min(x.wrapping_sub(bound))`.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_once_u64x4(x: __m256i, bound: __m256i) -> __m256i {
    let msb = _mm256_set1_epi64x(i64::MIN);
    // x < bound (unsigned)  ⇔  (x ^ MSB) < (bound ^ MSB) (signed)
    let mask = _mm256_cmpgt_epi64(_mm256_xor_si256(bound, msb), _mm256_xor_si256(x, msb));
    // mask = all 1s where x < bound, all 0s where x >= bound
    // blendv: if mask bit 7 set → take x, else take x - bound
    let sub = _mm256_sub_epi64(x, bound);
    _mm256_blendv_epi8(sub, x, mask)
}

/// `x mod q` for `x < 4*q` on 4 u64 lanes.
///
/// Two-step reduction: first modulo `2q`, then modulo `q`.
#[target_feature(enable = "avx2")]
#[inline]
fn reduce_twice_u64x4(x: __m256i, q: __m256i, two_q: __m256i) -> __m256i {
    let x = reduce_once_u64x4(x, two_q); // -> [0, 2q)
    reduce_once_u64x4(x, q) // -> [0, q)
}

// ---------------------------------------------------------------------------
// 64 × 64 → 128 widening multiply (4 lanes)
// ---------------------------------------------------------------------------

/// Returns `(lo, hi)` where `lo` and `hi` are the low and high 64 bits of
/// the 128-bit products `a * b` for each of the 4 u64 lanes.
///
/// Algorithm from <https://stackoverflow.com/a/28827013>: each 64-bit
/// operand is split into two 32-bit halves, then 4 cross-products are
/// computed via `_mm256_mul_epu32`.
#[allow(dead_code)]
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_u64x4(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    let lo_mask = _mm256_set1_epi64x(0x0000_0000_FFFF_FFFFu64 as i64);
    // Swap 32-bit halves within each 64-bit lane: [a1, a0] → [a0, a1]
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);

    // 32 × 32 → 64 cross-products
    let z_lo_lo = _mm256_mul_epu32(a, b); // a_lo * b_lo
    let z_lo_hi = _mm256_mul_epu32(a, b_hi); // a_lo * b_hi
    let z_hi_lo = _mm256_mul_epu32(a_hi, b); // a_hi * b_lo
    let z_hi_hi = _mm256_mul_epu32(a_hi, b_hi); // a_hi * b_hi — only needed for full / hi

    // --- low 64 bits ---
    // prod_lo = (z_lo_hi + z_hi_lo) << 32  +  z_lo_lo
    let prod_lo = _mm256_add_epi64(
        _mm256_slli_epi64::<32>(_mm256_add_epi64(z_lo_hi, z_hi_lo)),
        z_lo_lo,
    );

    // --- high 64 bits ---
    let z_lo_lo_shift = _mm256_srli_epi64::<32>(z_lo_lo); // carry from lo
    let sum_tmp = _mm256_add_epi64(z_lo_hi, z_lo_lo_shift);
    let sum_lo = _mm256_and_si256(sum_tmp, lo_mask); // low 32 bits of sum
    let sum_mid = _mm256_srli_epi64::<32>(sum_tmp); // carry to high

    let sum_mid2 = _mm256_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm256_srli_epi64::<32>(sum_mid2); // carry to highest
    let sum_hi = _mm256_add_epi64(z_hi_hi, sum_mid);

    let prod_hi = _mm256_add_epi64(sum_hi, sum_mid2_hi);

    (prod_lo, prod_hi)
}

/// Returns only the **high** 64 bits of `a * b` (4 lanes).
///
/// Saves ~3 instructions vs `widening_mul_u64x4` by skipping the low
/// recombination.  Used by `mul_mod_lazy_u64x4` for the qhat computation.
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_hi_u64x4(a: __m256i, b: __m256i) -> __m256i {
    let lo_mask = _mm256_set1_epi64x(0x0000_0000_FFFF_FFFFu64 as i64);
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);
    let z_lo_lo = _mm256_mul_epu32(a, b);
    let z_lo_hi = _mm256_mul_epu32(a, b_hi);
    let z_hi_lo = _mm256_mul_epu32(a_hi, b);
    let z_hi_hi = _mm256_mul_epu32(a_hi, b_hi);

    let z_lo_lo_shift = _mm256_srli_epi64::<32>(z_lo_lo);
    let sum_tmp = _mm256_add_epi64(z_lo_hi, z_lo_lo_shift);
    let sum_lo = _mm256_and_si256(sum_tmp, lo_mask);
    let sum_mid = _mm256_srli_epi64::<32>(sum_tmp);
    let sum_mid2 = _mm256_add_epi64(z_hi_lo, sum_lo);
    let sum_mid2_hi = _mm256_srli_epi64::<32>(sum_mid2);
    let sum_hi = _mm256_add_epi64(z_hi_hi, sum_mid);
    _mm256_add_epi64(sum_hi, sum_mid2_hi)
}

/// Returns only the **low** 64 bits of `a * b` (4 lanes).
///
/// Saves 1 `vpmuludq` + ~3 shift/add ops vs `widening_mul_u64x4` by
/// skipping `z_hi_hi` and the full high recombination.
/// Used by `mul_mod_lazy_u64x4` for the two low-half products.
#[target_feature(enable = "avx2")]
#[inline]
fn widening_mul_lo_u64x4(a: __m256i, b: __m256i) -> __m256i {
    let a_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(a);
    let b_hi = _mm256_shuffle_epi32::<0b10_11_00_01>(b);
    let z_lo_lo = _mm256_mul_epu32(a, b);
    let z_lo_hi = _mm256_mul_epu32(a, b_hi);
    let z_hi_lo = _mm256_mul_epu32(a_hi, b);
    // z_hi_hi is NOT computed — not needed for the low 64 bits.
    _mm256_add_epi64(
        _mm256_slli_epi64::<32>(_mm256_add_epi64(z_lo_hi, z_hi_lo)),
        z_lo_lo,
    )
}

// ---------------------------------------------------------------------------
// Barrett lazy multiply for 64-bit
// ---------------------------------------------------------------------------

/// Barrett-64 lazy multiply for 4 u64 lanes.
///
/// Computes `qhat = hi64(y * wp)` then `t = lo64(y * w) - lo64(q * qhat)`.
/// Uses `widening_mul_hi_u64x4` for the high half and
/// `widening_mul_lo_u64x4` for the two low halves, saving 2 `vpmuludq`
/// per butterfly vs calling the full `widening_mul_u64x4` each time.
#[target_feature(enable = "avx2")]
#[inline]
fn mul_mod_lazy_u64x4(y: __m256i, w: __m256i, wp: __m256i, q: __m256i) -> __m256i {
    let qhat = widening_mul_hi_u64x4(y, wp);
    let wy = widening_mul_lo_u64x4(y, w);
    let qq = widening_mul_lo_u64x4(q, qhat);
    _mm256_sub_epi64(wy, qq)
}

// ---------------------------------------------------------------------------
// T2 (t=2) load / store
// ---------------------------------------------------------------------------

/// Load 2 T2 blocks (8 u64) and deinterleave into x and y vectors.
///
/// T2 layout: each block is `[x₀,x₁ | y₀,y₁]` (4 u64 = 256 bits).
/// Two consecutive blocks A, B produce:
///
/// ```text
/// v_x = [x_B0, x_B1 | x_A0, x_A1]
/// v_y = [y_B0, y_B1 | y_A0, y_A1]
/// ```
///
/// W vector must be `[W_B, W_B | W_A, W_A]` (each twiddle duplicated
/// for the two butterflies in its block).
#[target_feature(enable = "avx2")]
#[inline]
fn t2_load_xy(block_a: *const __m256i, block_b: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures pointers are valid and point to live data.
    let v_a = unsafe { _mm256_loadu_si256(block_a) };
    let v_b = unsafe { _mm256_loadu_si256(block_b) };
    // permute2x128 0x20: lo 128 from a, lo 128 from b → xs
    let v_x = _mm256_permute2x128_si256::<0x20>(v_a, v_b);
    // 0x31: hi 128 from a, hi 128 from b → ys
    let v_y = _mm256_permute2x128_si256::<0x31>(v_a, v_b);
    (v_x, v_y)
}

/// Re-interleave x/y vectors back into two T2 blocks and store.
#[target_feature(enable = "avx2")]
#[inline]
fn t2_store_xy(v_x: __m256i, v_y: __m256i, block_a: *mut __m256i, block_b: *mut __m256i) {
    // Reverse of load: xs → lo, ys → hi
    let v_a = _mm256_permute2x128_si256::<0x20>(v_x, v_y);
    let v_b = _mm256_permute2x128_si256::<0x31>(v_x, v_y);
    // SAFETY: caller ensures pointers are valid and point to writable memory.
    unsafe {
        _mm256_storeu_si256(block_a, v_a);
        _mm256_storeu_si256(block_b, v_b);
    }
}

// ---------------------------------------------------------------------------
// T1 (t=1) load / store
// ---------------------------------------------------------------------------

/// Load 4 T1 blocks (8 u64) and deinterleave into x and y vectors.
///
/// T1 layout: each block is `[x | y]` (2 u64 = 128 bits).
/// Four consecutive blocks 0..3 produce:
///
/// ```text
/// v_x = [x₃, x₂, x₁, x₀]
/// v_y = [y₃, y₂, y₁, y₀]
/// ```
///
/// W vector is `[W₃, W₂, W₁, W₀]` — same lane order.
#[target_feature(enable = "avx2")]
#[inline]
fn t1_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures ptr points to at least 2 consecutive __m256i.
    let v0 = unsafe { _mm256_loadu_si256(ptr) }; // [x0, y0, x1, y1]
    let v1 = unsafe { _mm256_loadu_si256(ptr.add(1)) }; // [x2, y2, x3, y3]

    // unpack at 64-bit granularity:
    // tx = [x0, x2, x1, x3],  ty = [y0, y2, y1, y3]
    let tx = _mm256_unpacklo_epi64(v0, v1);
    let ty = _mm256_unpackhi_epi64(v0, v1);

    // Reverse lane order so upper lane = higher block index
    let v_x = _mm256_permute4x64_epi64::<0b00_10_01_11>(tx); // [x3, x2, x1, x0]
    let v_y = _mm256_permute4x64_epi64::<0b00_10_01_11>(ty); // [y3, y2, y1, y0]
    (v_x, v_y)
}

/// Re-interleave x/y vectors back into four T1 blocks and store.
#[target_feature(enable = "avx2")]
#[inline]
fn t1_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
    // Reverse the deinterleave permutation
    let tx = _mm256_permute4x64_epi64::<0b00_10_01_11>(v_x); // [x0, x2, x1, x3]
    let ty = _mm256_permute4x64_epi64::<0b00_10_01_11>(v_y); // [y0, y2, y1, y3]

    // Interleave back
    let v0 = _mm256_unpacklo_epi64(tx, ty); // [x0, y0, x1, y1]
    let v1 = _mm256_unpackhi_epi64(tx, ty); // [x2, y2, x3, y3]

    // SAFETY: caller ensures ptr points to at least 2 writable __m256i.
    unsafe {
        _mm256_storeu_si256(ptr, v0);
        _mm256_storeu_si256(ptr.add(1), v1);
    }
}

// ---------------------------------------------------------------------------
// Butterflies
// ---------------------------------------------------------------------------

/// Forward Harvey butterfly on 4 u64 lanes.
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
fn fwd_butterfly_u64x4(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let x0 = reduce_once_u64x4(x, two_q);
    let t = mul_mod_lazy_u64x4(y, w, wp, q);
    let x_new = _mm256_add_epi64(x0, t);
    let y_new = _mm256_sub_epi64(_mm256_add_epi64(x0, two_q), t);
    (x_new, y_new)
}

/// Forward butterfly variant that skips `reduce_once(x, two_q)`.
///
/// Only valid when the caller guarantees `x < 2q` in every lane.
/// Used in the first stage when `input_mod_factor <= 2`.
#[target_feature(enable = "avx2")]
#[inline]
fn fwd_butterfly_u64x4_no_reduce_x(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let t = mul_mod_lazy_u64x4(y, w, wp, q);
    let x_new = _mm256_add_epi64(x, t);
    let y_new = _mm256_sub_epi64(_mm256_add_epi64(x, two_q), t);
    (x_new, y_new)
}

/// Inverse Harvey butterfly on 4 u64 lanes.
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
fn inv_butterfly_u64x4(
    x: __m256i,
    y: __m256i,
    w: __m256i,
    wp: __m256i,
    q: __m256i,
    two_q: __m256i,
) -> (__m256i, __m256i) {
    let s = _mm256_add_epi64(x, y);
    let d = _mm256_sub_epi64(_mm256_add_epi64(x, two_q), y);
    let x_new = reduce_once_u64x4(s, two_q);
    let y_new = mul_mod_lazy_u64x4(d, w, wp, q);
    (x_new, y_new)
}

impl U64NttTable {
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
    /// - `values.len()` is a power of two and ≥ 16.
    /// - `roots.len() == values.len()` and `roots_precon.len() == values.len()`.
    /// - `q < 2^62`.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn avx2_forward_transform(
        &self,
        values: &mut [u64],
        input_mod_factor: u32,
        output_mod_factor: u32,
    ) {
        let n = self.n;

        // Polynomial lengths below 16 are trivial — delegate to scalar.
        if n < 16 {
            return self.scalar_forward_transform(values, input_mod_factor, output_mod_factor);
        }

        assert_eq!(values.len(), n);

        debug_assert!(
            matches!(input_mod_factor, 1 | 2 | 4),
            "input_mod_factor must be 1, 2 or 4; got {input_mod_factor}"
        );
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 4,
            "output_mod_factor must be 1 or 4; got {output_mod_factor}"
        );

        let q = self.q;
        let two_q = self.two_q;

        let roots = self.roots.as_slice();
        let roots_precon = self.roots_precon.as_slice();

        let v_q = _mm256_set1_epi64x(q as i64);
        let v_two_q = _mm256_set1_epi64x(two_q as i64);

        let skip_first_reduce_x = input_mod_factor <= 2;
        let mut is_first_stage = true;

        // Direct index: avoid zip+map overhead.
        let mut ri = 1usize; // skip roots[0] = 1
        let mut t = n >> 1;
        let mut m = 1;

        while m < n {
            let reduce_x = !(is_first_stage && skip_first_reduce_x);
            is_first_stage = false;

            if t >= 4 {
                // --- AVX2 path: t ≥ 4, process 4 butterflies per inner iteration ---
                for block in values.chunks_exact_mut(t * 2) {
                    // SAFETY: ri is always < roots.len().
                    let w = unsafe { *roots.get_unchecked(ri) };
                    let wp = unsafe { *roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm256_set1_epi64x(w as i64);
                    let v_wp = _mm256_set1_epi64x(wp as i64);

                    // SAFETY: block.len() == 2t, t ≥ 4, so split is valid.
                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };

                    // SAFETY: xs.len() == ys.len() == t, t is a multiple of 4.
                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<4>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<4>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let v_y =
                            unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let (v_x, v_y) = if reduce_x {
                            fwd_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                        } else {
                            fwd_butterfly_u64x4_no_reduce_x(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                        };
                        unsafe {
                            _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_x);
                            _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_y);
                        }
                    }
                }
            } else {
                // --- t < 4 stages (n ≥ 16 guaranteed, all AVX2) ---
                match t {
                    2 => {
                        // SAFETY: n is a power of two ≥ 16, so chunking into 8 is valid.
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                        for chunk in chunks {
                            let w_a = unsafe { *roots.get_unchecked(ri) };
                            let wp_a = unsafe { *roots_precon.get_unchecked(ri) };
                            ri += 1;
                            let w_b = unsafe { *roots.get_unchecked(ri) };
                            let wp_b = unsafe { *roots_precon.get_unchecked(ri) };
                            ri += 1;

                            // W: [W_B, W_B | W_A, W_A] — lanes 3,2 use W_B; lanes 1,0 use W_A
                            let v_w =
                                _mm256_set_epi64x(w_b as i64, w_b as i64, w_a as i64, w_a as i64);
                            let v_wp = _mm256_set_epi64x(
                                wp_b as i64,
                                wp_b as i64,
                                wp_a as i64,
                                wp_a as i64,
                            );

                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t2_load_xy(ptr, unsafe { ptr.add(1) });
                            let (v_x, v_y) = if reduce_x {
                                fwd_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                            } else {
                                fwd_butterfly_u64x4_no_reduce_x(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                            };
                            t2_store_xy(v_x, v_y, ptr, unsafe { ptr.add(1) });
                        }
                    }
                    1 => {
                        // SAFETY: n is a power of two ≥ 16.
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                        if output_mod_factor == 1 {
                            for chunk in chunks {
                                let v_w_raw = unsafe {
                                    _mm256_loadu_si256(roots.as_ptr().add(ri).cast::<__m256i>())
                                };
                                let v_w = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_w_raw);
                                let v_wp_raw = unsafe {
                                    _mm256_loadu_si256(
                                        roots_precon.as_ptr().add(ri).cast::<__m256i>(),
                                    )
                                };
                                let v_wp = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_wp_raw);
                                ri += 4;

                                let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                                let (v_x, v_y) = t1_load_xy(ptr);
                                let (v_x, v_y) = if reduce_x {
                                    fwd_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                                } else {
                                    fwd_butterfly_u64x4_no_reduce_x(
                                        v_x, v_y, v_w, v_wp, v_q, v_two_q,
                                    )
                                };
                                let v_x = reduce_twice_u64x4(v_x, v_q, v_two_q);
                                let v_y = reduce_twice_u64x4(v_y, v_q, v_two_q);
                                t1_store_xy(v_x, v_y, ptr);
                            }
                        } else {
                            for chunk in chunks {
                                let v_w_raw = unsafe {
                                    _mm256_loadu_si256(roots.as_ptr().add(ri).cast::<__m256i>())
                                };
                                let v_w = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_w_raw);
                                let v_wp_raw = unsafe {
                                    _mm256_loadu_si256(
                                        roots_precon.as_ptr().add(ri).cast::<__m256i>(),
                                    )
                                };
                                let v_wp = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_wp_raw);
                                ri += 4;

                                let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                                let (v_x, v_y) = t1_load_xy(ptr);
                                let (v_x, v_y) = if reduce_x {
                                    fwd_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q)
                                } else {
                                    fwd_butterfly_u64x4_no_reduce_x(
                                        v_x, v_y, v_w, v_wp, v_q, v_two_q,
                                    )
                                };
                                t1_store_xy(v_x, v_y, ptr);
                            }
                        }
                    }
                    _ => unreachable!("t < 4 and t is a power of two => t ∈ {{1, 2}}"),
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
    /// - `q < 2^62`.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn avx2_inverse_transform(
        &self,
        values: &mut [u64],
        input_mod_factor: u32,
        output_mod_factor: u32,
    ) {
        let n = self.n;

        if n < 16 {
            return self.scalar_inverse_transform(values, input_mod_factor, output_mod_factor);
        }

        assert_eq!(values.len(), n);

        debug_assert!(
            input_mod_factor == 1 || input_mod_factor == 2,
            "input_mod_factor must be 1 or 2; got {input_mod_factor}"
        );
        debug_assert!(
            output_mod_factor == 1 || output_mod_factor == 2,
            "output_mod_factor must be 1 or 2; got {output_mod_factor}"
        );

        let q = self.q;
        let two_q = self.two_q;

        let inv_n = self.inv_n;
        let inv_n_precon = self.inv_n_precon;
        let inv_n_w = self.inv_n_w;
        let inv_n_w_precon = self.inv_n_w_precon;
        let inv_roots = self.inv_roots.as_slice();
        let inv_roots_precon = self.inv_roots_precon.as_slice();

        let v_q = _mm256_set1_epi64x(q as i64);
        let v_two_q = _mm256_set1_epi64x(two_q as i64);

        let mut ri = 1usize; // skip inv_roots[0] = 1
        let mut t = 1usize;
        let mut m = n >> 1;

        while m > 1 {
            if t >= 4 {
                // --- AVX2 path ---
                for block in values.chunks_exact_mut(t * 2) {
                    let w = unsafe { *inv_roots.get_unchecked(ri) };
                    let wp = unsafe { *inv_roots_precon.get_unchecked(ri) };
                    ri += 1;

                    let v_w = _mm256_set1_epi64x(w as i64);
                    let v_wp = _mm256_set1_epi64x(wp as i64);

                    let (xs, ys) = unsafe { block.split_at_mut_unchecked(t) };
                    let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<4>() };
                    let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<4>() };
                    for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                        let v_x =
                            unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let v_y =
                            unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };
                        let (v_x, v_y) = inv_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                        unsafe {
                            _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_x);
                            _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_y);
                        }
                    }
                }
            } else {
                // --- t < 4 stages ---
                match t {
                    1 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                        for chunk in chunks {
                            let v_w_raw = unsafe {
                                _mm256_loadu_si256(inv_roots.as_ptr().add(ri).cast::<__m256i>())
                            };
                            let v_w = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_w_raw);
                            let v_wp_raw = unsafe {
                                _mm256_loadu_si256(
                                    inv_roots_precon.as_ptr().add(ri).cast::<__m256i>(),
                                )
                            };
                            let v_wp = _mm256_permute4x64_epi64::<0b00_01_10_11>(v_wp_raw);
                            ri += 4;

                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t1_load_xy(ptr);
                            let (v_x, v_y) = inv_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t1_store_xy(v_x, v_y, ptr);
                        }
                    }
                    2 => {
                        let chunks = unsafe { values.as_chunks_unchecked_mut::<8>() };
                        for chunk in chunks {
                            let w_a = unsafe { *inv_roots.get_unchecked(ri) };
                            let wp_a = unsafe { *inv_roots_precon.get_unchecked(ri) };
                            ri += 1;
                            let w_b = unsafe { *inv_roots.get_unchecked(ri) };
                            let wp_b = unsafe { *inv_roots_precon.get_unchecked(ri) };
                            ri += 1;

                            let v_w =
                                _mm256_set_epi64x(w_b as i64, w_b as i64, w_a as i64, w_a as i64);
                            let v_wp = _mm256_set_epi64x(
                                wp_b as i64,
                                wp_b as i64,
                                wp_a as i64,
                                wp_a as i64,
                            );

                            let ptr = chunk.as_mut_ptr().cast::<__m256i>();
                            let (v_x, v_y) = t2_load_xy(ptr, unsafe { ptr.add(1) });
                            let (v_x, v_y) = inv_butterfly_u64x4(v_x, v_y, v_w, v_wp, v_q, v_two_q);
                            t2_store_xy(v_x, v_y, ptr, unsafe { ptr.add(1) });
                        }
                    }
                    _ => unreachable!("t < 4 and t is a power of two => t ∈ {{1, 2}}"),
                }
            }
            t <<= 1;
            m >>= 1;
        }

        // --- Final stage: fused with inv_n multiply (inv_n_w precomputed) ---
        // --- AVX2 final stage: n/2 ≥ 8 (guaranteed since n ≥ 16) ---
        let v_inv_n = _mm256_set1_epi64x(inv_n as i64);
        let v_inv_n_w = _mm256_set1_epi64x(inv_n_w as i64);
        let v_inv_n_precon = _mm256_set1_epi64x(inv_n_precon as i64);
        let v_inv_n_w_precon = _mm256_set1_epi64x(inv_n_w_precon as i64);

        let (xs, ys) = unsafe { values.split_at_mut_unchecked(n / 2) };
        let xs_chunks = unsafe { xs.as_chunks_unchecked_mut::<4>() };
        let ys_chunks = unsafe { ys.as_chunks_unchecked_mut::<4>() };
        if output_mod_factor == 1 {
            for (x_chunk, y_chunk) in xs_chunks.iter_mut().zip(ys_chunks) {
                let v_x = unsafe { _mm256_loadu_si256(x_chunk.as_mut_ptr().cast::<__m256i>()) };
                let v_y = unsafe { _mm256_loadu_si256(y_chunk.as_mut_ptr().cast::<__m256i>()) };

                let v_sum = _mm256_add_epi64(v_x, v_y);
                let v_tx = reduce_once_u64x4(v_sum, v_two_q);
                let v_ty = _mm256_sub_epi64(_mm256_add_epi64(v_x, v_two_q), v_y);

                let v_new_x =
                    reduce_once_u64x4(mul_mod_lazy_u64x4(v_tx, v_inv_n, v_inv_n_precon, v_q), v_q);
                let v_new_y = reduce_once_u64x4(
                    mul_mod_lazy_u64x4(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q),
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

                let v_sum = _mm256_add_epi64(v_x, v_y);
                let v_tx = reduce_once_u64x4(v_sum, v_two_q);
                let v_ty = _mm256_sub_epi64(_mm256_add_epi64(v_x, v_two_q), v_y);

                let v_new_x = mul_mod_lazy_u64x4(v_tx, v_inv_n, v_inv_n_precon, v_q);
                let v_new_y = mul_mod_lazy_u64x4(v_ty, v_inv_n_w, v_inv_n_w_precon, v_q);

                unsafe {
                    _mm256_storeu_si256(x_chunk.as_mut_ptr().cast::<__m256i>(), v_new_x);
                    _mm256_storeu_si256(y_chunk.as_mut_ptr().cast::<__m256i>(), v_new_y);
                }
            }
        }
    }
}

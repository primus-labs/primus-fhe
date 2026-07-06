use core::arch::x86_64::*;

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
pub(super) fn t4_load_xy(block_a: *const __m256i, block_b: *const __m256i) -> (__m256i, __m256i) {
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
pub(super) fn t4_store_xy(
    v_x: __m256i,
    v_y: __m256i,
    block_a: *mut __m256i,
    block_b: *mut __m256i,
) {
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
pub(super) fn t2_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures ptr points to 2 consecutive __m256i.
    let v0 = unsafe { _mm256_loadu_si256(ptr) };
    let v1 = unsafe { _mm256_loadu_si256(ptr.add(1)) };
    let v_x = _mm256_unpacklo_epi64(v0, v1);
    let v_y = _mm256_unpackhi_epi64(v0, v1);
    (v_x, v_y)
}

#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn t2_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
    let v0 = _mm256_unpacklo_epi64(v_x, v_y);
    let v1 = _mm256_unpackhi_epi64(v_x, v_y);

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
/// Low-to-high output lanes are:
///
/// ```text
/// v_x = [x0,x1,x4,x5, x2,x3,x6,x7]
/// v_y = [y0,y1,y4,y5, y2,y3,y6,y7]
/// ```
///
/// The corresponding W vector must use the same low-to-high lane order:
/// `[W0,W1,W4,W5, W2,W3,W6,W7]`.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn t1_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
    // SAFETY: caller ensures ptr points to 2 consecutive __m256i.
    let v0 = unsafe { _mm256_loadu_si256(ptr) };
    let v1 = unsafe { _mm256_loadu_si256(ptr.add(1)) };

    // Within each 128-bit half: [x0,y0,x1,y1] -> [x0,x1,y0,y1].
    let s0 = _mm256_shuffle_epi32::<0xD8>(v0);
    let s1 = _mm256_shuffle_epi32::<0xD8>(v1);

    let v_x = _mm256_unpacklo_epi64(s0, s1);
    let v_y = _mm256_unpackhi_epi64(s0, s1);
    (v_x, v_y)
}

#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn t1_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
    let s0 = _mm256_unpacklo_epi64(v_x, v_y);
    let s1 = _mm256_unpackhi_epi64(v_x, v_y);

    let v0 = _mm256_shuffle_epi32::<0xD8>(s0);
    let v1 = _mm256_shuffle_epi32::<0xD8>(s1);

    // SAFETY: caller ensures ptr points to 2 writable __m256i.
    unsafe {
        _mm256_storeu_si256(ptr, v0);
        _mm256_storeu_si256(ptr.add(1), v1);
    }
}

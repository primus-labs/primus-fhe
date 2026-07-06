use core::arch::x86_64::*;

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
pub(super) fn t2_load_xy(block_a: *const __m256i, block_b: *const __m256i) -> (__m256i, __m256i) {
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
pub(super) fn t2_store_xy(
    v_x: __m256i,
    v_y: __m256i,
    block_a: *mut __m256i,
    block_b: *mut __m256i,
) {
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
pub(super) fn t1_load_xy(ptr: *const __m256i) -> (__m256i, __m256i) {
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
pub(super) fn t1_store_xy(v_x: __m256i, v_y: __m256i, ptr: *mut __m256i) {
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

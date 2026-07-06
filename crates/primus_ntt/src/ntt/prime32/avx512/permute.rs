use core::arch::x86_64::*;

use super::arithmetic::reduce_twice_avx512;
use super::butterfly::{fwd_butterfly_avx512, inv_butterfly_avx512};

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
// Generic deinterleave helpers
// ---------------------------------------------------------------------------

/// Pre-loaded permutation masks for one deinterleave stage.
pub(super) struct DeinterleaveMasks {
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

    pub(super) fn for_t(t: usize) -> Self {
        unsafe {
            match t {
                8 => Self::load(&PERM_T8_X, &PERM_T8_Y, &PERM_T8_A, &PERM_T8_B),
                4 => Self::load(&PERM_T4_X, &PERM_T4_Y, &PERM_T4_STORE_A, &PERM_T4_STORE_B),
                2 => Self::load(&PERM_T2_X, &PERM_T2_Y, &PERM_T2_STORE_A, &PERM_T2_STORE_B),
                1 => Self::load(&PERM_T1_X, &PERM_T1_Y, &PERM_T1_STORE_A, &PERM_T1_STORE_B),
                _ => unreachable!(),
            }
        }
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_t8(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x44>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xEE>(v_a, v_b);
        let (v_x, v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_shuffle_i32x4::<0x44>(v_x, v_y);
        let b_out = _mm512_shuffle_i32x4::<0xEE>(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_t8(
    ptr: *mut __m512i,
    v_w: __m512i,
    v_wp: __m512i,
    v_q: __m512i,
    v_two_q: __m512i,
) {
    unsafe {
        let v_a = _mm512_loadu_si512(ptr);
        let v_b = _mm512_loadu_si512(ptr.add(1));

        let v_x = _mm512_shuffle_i32x4::<0x44>(v_a, v_b);
        let v_y = _mm512_shuffle_i32x4::<0xEE>(v_a, v_b);
        let (v_x, v_y) = inv_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);

        let a_out = _mm512_shuffle_i32x4::<0x44>(v_x, v_y);
        let b_out = _mm512_shuffle_i32x4::<0xEE>(v_x, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

/// Load two `__m512i`, deinterleave, butterfly, optionally reduce to `[0,q)`,
/// then re-interleave and store.
///
/// When `REDUCE` is true, `reduce_twice_avx512` is applied to the
/// butterfly output before re-interleaving — this fuses the canonical reduction
/// for the final (t=1) stage.
#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_fwd_stage<const REDUCE: bool>(
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
        let (mut v_x, mut v_y) = fwd_butterfly_avx512(v_x, v_y, v_w, v_wp, v_q, v_two_q);
        if REDUCE {
            v_x = reduce_twice_avx512(v_x, v_q, v_two_q);
            v_y = reduce_twice_avx512(v_y, v_q, v_two_q);
        }
        let a_out = _mm512_permutex2var_epi32(v_x, masks.idx_sa, v_y);
        let b_out = _mm512_permutex2var_epi32(v_x, masks.idx_sb, v_y);
        _mm512_storeu_si512(ptr, a_out);
        _mm512_storeu_si512(ptr.add(1), b_out);
    }
}

#[target_feature(enable = "avx512f")]
#[inline]
pub(super) fn deinterleave_inv_stage(
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

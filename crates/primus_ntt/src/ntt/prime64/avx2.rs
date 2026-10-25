//! AVX2-accelerated forward and inverse NTT transforms for u64.
//!
//! Uses 256-bit vectors (4 × u64 lanes).  Because AVX2 lacks native packed
//! 64 × 64 → 128 multiplication, the needed high or low half is computed by
//! 32-bit limb products and carry recombination, adapted from
//! <https://stackoverflow.com/a/28827013>.
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
//! The table dispatcher calls the unsafe transform entry points only after
//! checking `is_x86_feature_detected!("avx2")` at table construction.
//! Helpers inherit that target feature; their local unsafe blocks are limited to
//! unchecked slicing and vector loads.

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime64) mod precompute;
mod transform;

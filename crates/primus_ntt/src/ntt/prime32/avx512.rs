//! AVX-512 accelerated forward and inverse NTT transforms for u32.
//!
//! Uses 512-bit vectors (16 × u32 lanes):
//! - T16 (t ≥ 16): broadcast W, contiguous x/y loads.
//! - T8 / T4: `shuffle_i32x4` groups 128-bit halves.
//! - T2: `unpacklo/hi_epi64` groups two-coefficient halves.
//! - T1: `shuffle_epi32` plus `unpacklo/hi_epi64` separates adjacent pairs.
//!
//! Requires `n ≥ 32` — polynomial lengths below that are handled by the
//! scalar backend directly.
//!
//! # Safety
//!
//! The table dispatcher calls the unsafe transform entry points only after
//! checking `is_x86_feature_detected!("avx512f")` at table construction.
//! Helpers inherit that target feature; their local unsafe blocks are limited to
//! unchecked slicing and vector loads.

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime32) mod precompute;
mod transform;

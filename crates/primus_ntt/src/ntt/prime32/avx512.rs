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
//! [`crate::constants::HAS_AVX512F`].

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime32) mod precompute;
mod transform;

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
//! [`crate::constants::HAS_AVX2`].  Internal helpers are safe `fn` (not `unsafe fn`)
//! because the `#[target_feature]` attribute ensures the right ISA is
//! available; only operations that dereference raw pointers or call
//! `_unchecked` slice methods need `unsafe {}` blocks.

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime32) mod precompute;
mod transform;

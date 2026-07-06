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

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime64) mod precompute;
mod transform;

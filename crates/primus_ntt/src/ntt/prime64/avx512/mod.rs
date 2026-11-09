//! AVX-512 NTT transform kernels translated from Intel HEXL.
//!
//! The stage decomposition deliberately remains close to HEXL's
//! `fwd-ntt-avx512.cpp` and `inv-ntt-avx512.cpp`: small transforms are
//! breadth-first, larger transforms recurse depth-first, and the packed T4/T2
//! forward stages consume the same expanded root layout. This makes arithmetic
//! or range changes reviewable against the upstream implementation.
//!
//! Rust-specific adaptations are kept at the boundaries: transforms are
//! in-place slices, fixed-size chunks replace pointer-counting loops, and table
//! construction supplies the inverse final-stage constants. The local
//! breadth-first cutoff is benchmarked independently of HEXL. The
//! `_mm512_hexl_*` arithmetic names remain where a one-to-one upstream
//! comparison is useful.

mod butterfly;
pub(super) mod internal;
pub(super) mod precompute;
mod stages;
pub(super) mod transform;
mod utils;

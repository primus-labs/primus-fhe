//! AVX-512 NTT transform kernels derived from Intel HEXL.
//!
//! This module lives under `ntt::u64` (re-exported as `crate::ntt::u64::hexl`)
//! and provides the building blocks used by `U64NttTable`'s AVX-512 dispatch.

mod butterfly;
pub(crate) mod internal;
pub(crate) mod precompute;
mod stages;
pub(crate) mod transform;
pub(crate) mod utils;

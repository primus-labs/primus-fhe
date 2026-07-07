#![deny(missing_docs)]
//! Number-theoretic transform (NTT) for homomorphic encryption.
//!
//! Provides forward and inverse NTT tables for `u32` and `u64` primes with
//! runtime dispatch to scalar, AVX2, and AVX-512 (DQ / IFMA) backends.

mod error;

pub(crate) mod constants;
mod dcrt;
mod ntt;
mod reverse;
mod root;

pub use dcrt::*;
pub use error::NttError;
pub use ntt::*;

pub use reverse::ReverseLsbs;
pub use root::PrimitiveRoot;

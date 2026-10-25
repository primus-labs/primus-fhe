#![deny(missing_docs)]
//! Number-theoretic transform (NTT) for homomorphic encryption.
//!
//! Provides forward and inverse NTT tables for `u32` and `u64` primes with
//! runtime dispatch to scalar, AVX2, and AVX-512 (DQ / IFMA) backends.

mod automorphism;
mod error;

mod dcrt;
mod ntt;
mod reverse;
mod root;

pub use automorphism::NttAutomorphismPermutation;
pub use dcrt::*;
pub use error::NttError;
pub use ntt::*;

/// Bits reserved for the lazy `[0, 4q)` representation.
pub(crate) const NTT_LAZY_REDUCTION_HEADROOM_BITS: u32 = 2;

/// Maximum coefficient-modulus bit length supported by the `u32` NTT tables.
///
/// The modulus itself must be strictly less than `2^U32_NTT_MAX_MODULUS_BITS`.
pub const U32_NTT_MAX_MODULUS_BITS: u32 = u32::BITS - NTT_LAZY_REDUCTION_HEADROOM_BITS;

/// Maximum coefficient-modulus bit length supported by the `u64` NTT tables.
///
/// The modulus itself must be strictly less than `2^U64_NTT_MAX_MODULUS_BITS`.
pub const U64_NTT_MAX_MODULUS_BITS: u32 = u64::BITS - NTT_LAZY_REDUCTION_HEADROOM_BITS;

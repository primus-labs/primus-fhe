//! Residue number system utilities for CRT-style integer and polynomial data.
//!
//! The crate centers on [`RNSBase`], which stores a pairwise-coprime modulus
//! basis and the CRT precomputations needed for decomposition and composition.
//! [`BaseConverter`] builds on two bases to convert residue vectors between
//! them, including batched polynomial layouts used by `primus_poly`.
//!
//! Layout conventions used by the public APIs:
//!
//! - `n` means `RNSBase::moduli_count()`.
//! - `value_len` means `RNSBase::big_uint_value_len()`.
//! - Batched residue arrays are modulus-major: for `k` values, the slice has
//!   `n * k` elements and chunk `i` of length `k` stores all residues modulo
//!   `moduli()[i]`.
//! - Batched big-integer arrays store `k` consecutive little-endian integers,
//!   each occupying `value_len` limbs.

#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

mod error;

mod base;
mod converter;

pub use error::RNSError;

pub use base::RNSBase;
pub use converter::BaseConverter;

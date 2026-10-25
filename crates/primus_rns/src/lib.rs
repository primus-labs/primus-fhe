//! Residue number system utilities for CRT-style integer and polynomial data.
//!
//! The crate centers on [`RNSBase`], which stores a pairwise-coprime modulus
//! basis and the CRT precomputations needed for decomposition and composition.
//! [`BaseConverter`] builds on two bases to convert residue vectors between
//! them. Batched operations use flat slices with caller-owned output and scratch,
//! without depending on polynomial container types.
//!
//! [`Residues`] represents one value under an ordered basis with owned or
//! borrowed storage; it does not store or validate the basis.
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
mod residue_factors;
mod residues;

pub use residue_factors::ResidueFactors;
pub use residues::Residues;

mod base;
mod converter;
pub mod hybrid;

pub use error::RnsError;

pub use base::RNSBase;
pub use converter::{BaseConverter, CorrectedConversionWorkspace};
pub use hybrid::{HybridRNS, HybridRNSPartition, HybridRNSPartitioning};

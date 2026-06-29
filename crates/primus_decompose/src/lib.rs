//! Decomposition operators for fully homomorphic encryption.
//!
//! Approximate signed decomposition is a core building block for FHE schemes
//! such as FHEW/TFHE. This crate provides two flavors:
//!
//! - [`primitive`] — operates on single-limb values (`T: FheUint`).
//! - [`big_integer`] — operates on multi-limb [`BigUint`] values.
//!
//! [`BigUint`]: primus_integer::BigUint

#![deny(missing_docs)]

/// Multi-limb decomposition operators and basis.
pub mod big_integer;
/// Single-limb (primitive) decomposition operators and basis.
pub mod primitive;

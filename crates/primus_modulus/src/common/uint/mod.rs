//! Kernels for a representable unsigned-integer modulus greater than one.
//!
//! Unless stated otherwise, operands are canonical residues for `modulus` and
//! results are canonical. Lazy negation may return `modulus` for zero. Inversion
//! requires a canonical input even for its fallible form: `Result` reports a
//! missing inverse, not invalid input ranges. These are caller obligations;
//! this module does not generally validate them.

mod primitive;
/// Slice-oriented helpers for unsigned-integer modular arithmetic.
pub mod slice;

/// SIMD implementations of the unsigned-integer helpers.
#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

//! Generic unsigned-integer modular arithmetic helpers.

mod primitive;
/// Slice-oriented helpers for unsigned-integer modular arithmetic.
pub mod slice;

/// SIMD implementations of the unsigned-integer helpers.
#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

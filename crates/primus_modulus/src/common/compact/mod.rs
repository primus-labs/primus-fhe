//! Modular arithmetic helpers for compact moduli.

mod primitive;
/// Slice-oriented helpers for compact modular arithmetic.
pub mod slice;

/// SIMD implementations of compact modular arithmetic helpers.
#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

/// Number of scalar products accumulated before reducing a dot-product chunk.
pub const DOT_PRODUCT_INNER_CHUNK: usize = 16;

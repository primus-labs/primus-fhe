//! Kernels for moduli satisfying `1 < m < 2^(BITS - 2)`.

mod primitive;
/// Slice-oriented helpers for compact modular arithmetic.
pub mod slice;

/// SIMD implementations of compact modular arithmetic helpers.
#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

/// Number of scalar products accumulated before reducing a dot-product chunk.
///
/// With each operand below `2^(BITS - 2)`, 16 products sum to
/// less than `2^(2 * BITS)` and therefore fit in two limbs.
pub(crate) const DOT_PRODUCT_INNER_CHUNK: usize = 16;

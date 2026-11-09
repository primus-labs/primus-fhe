//! Low-level kernels used by compact modulus contexts and lazy NTT arithmetic.
//!
//! The context's `m < 2^(BITS - 2)` bound is not a universal restriction on
//! these free functions. Addition, doubling and subtraction need canonical
//! inputs and `2 * m <= 2^BITS`; single-correction reduction accepts a
//! representable value below `2 * m`. In particular, an NTT may pass `2q` as
//! the modulus when its table guarantees `q < 2^(BITS - 2)`.
//! Multiplication and dot-product helpers retain their own documented bounds.
//! None of these mathematical conditions is generally validated here.

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

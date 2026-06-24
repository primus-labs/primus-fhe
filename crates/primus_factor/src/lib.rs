//! Precomputed factors for accelerating modular arithmetic.
//!
//! This crate provides factor types such as [`ShoupFactor`] for workloads that
//! repeatedly multiply by the same value under a fixed modulus.

#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

pub(crate) mod common;
mod ops;

mod mul_factor;
mod shoup_factor;

pub use ops::*;

pub use mul_factor::MultiplyFactor;
pub use shoup_factor::ShoupFactor;

#[cfg(feature = "simd")]
pub use shoup_factor::SimdShoupFactor;

/// Marker trait for complete scalar and slice-level precomputed-factor operations.
///
/// A factor can multiply one value or a slice in lazy and canonical modular
/// forms. The modulus passed to each operation must match the modulus used to
/// construct or reset the factor.
pub trait Factor<T>: Copy + LazyFactorMul<T> + FactorMul<T> + FactorSliceOps<T> {}

impl<T, F> Factor<T> for F where F: Copy + LazyFactorMul<T> + FactorMul<T> + FactorSliceOps<T> {}

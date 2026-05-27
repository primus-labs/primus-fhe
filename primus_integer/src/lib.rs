//! Integer trait hierarchies and big-integer arithmetic.
//!
//! `primus_integer` provides [`Integer`] and [`UnsignedInteger`] — the core
//! numeric trait hierarchies used throughout the primus workspace — together
//! with [`BigUint`] for arbitrary-precision unsigned integers.
//!
//! When the `simd` feature is enabled (requires nightly), SIMD vector
//! abstractions ([`SimdArray`], [`SimdMaskArray`], [`SimdUnsignedInteger`])
//! are also available.

#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

mod macros;

mod integer_traits;

mod integer;
mod unsigned_integer;

mod big_integer;

#[cfg(feature = "simd")]
mod simd;

mod size;
pub use size::Size;

pub use integer_traits::*;

pub use integer::{FheInt, Integer};
pub use unsigned_integer::{FheUint, UnsignedInteger};

pub use big_integer::{
    BigUint, BigUintIter, BigUintIterMut, BigUintMut, BigUintOwned, BigUintRef,
    multiply_many_values, multiply_many_values_except, multiply_many_values_except_inplace,
};

#[cfg(feature = "simd")]
pub use simd::{SimdArray, SimdMaskArray, SimdUnsignedInteger};

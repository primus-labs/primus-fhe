//! Integer trait hierarchies and big-integer arithmetic.
//!
//! `primus_integer` provides [`Integer`], [`SignedInteger`], and
//! [`UnsignedInteger`] — the core numeric trait hierarchies used throughout
//! the primus workspace — together with [`BigUint`] for fixed-width,
//! multi-limb unsigned integers.
//!
//! The optional `serde` feature enables serialization of [`BigUint`] when its
//! backing storage supports it; integer arithmetic traits have no serde bounds.
//!
//! When the `simd` feature is enabled (requires nightly), SIMD vector
//! abstractions (SimdArray, SimdInteger, SimdMaskArray, SimdUnsignedInteger)
//! are also available.

#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

mod integer_traits;

mod integer;
mod signed_integer;
mod unsigned_integer;

mod big_integer;

#[cfg(feature = "simd")]
mod simd;

mod size;
pub use size::Size;

pub use integer_traits::*;

pub use integer::{FheInt, Integer};
pub use signed_integer::SignedInteger;
pub use unsigned_integer::{FheUint, UnsignedInteger};

pub use big_integer::{
    BigUint, BigUintIter, BigUintIterMut, BigUintMut, BigUintOwned, BigUintRef,
    multiply_many_values,
};

#[cfg(feature = "simd")]
pub use simd::{
    LaneArray, SimdArray, SimdInteger, SimdMaskArray, SimdUnsignedArray, SimdUnsignedInteger,
};

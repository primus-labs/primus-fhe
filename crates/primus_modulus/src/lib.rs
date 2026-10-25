#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

//! Concrete modulus types implementing the [`primus_reduce`] traits.
//!
//! | Type | Reduction | Use case |
//! |------|-----------|----------|
//! | [`NativeModulus`] | Wrapping arithmetic | Implicit modulus `2^BITS` |
//! | [`PowOf2Modulus`] | Bit masking | Representable power-of-two modulus |
//! | [`BarrettModulus`] | Barrett reduction (`m < 2^(BITS - 2)`) | Repeated multiplication and reduction |
//! | [`CompactModulus`] | Bounded arithmetic (`m < 2^(BITS - 2)`) | Basic operations without precomputation |
//! | [`UintModulus`] | Generic unsigned arithmetic | Basic operations for any representable `m > 1` |
//!
//! [`ModulusConfig`] describes Native, PowOf2 or Barrett choices in constants;
//! use the selected reducer's `TryFrom` implementation to validate and prepare it.
//!
//! # Example
//!
//! ```
//! use primus_modulus::{BarrettModulus, reduce::prelude::*};
//!
//! let modulus = BarrettModulus::new(97u64);
//!
//! assert_eq!(modulus.reduce_add(80, 30), 13);
//! assert_eq!(modulus.reduce_mul(12, 9), 11);
//!
//! let lhs = [12, 20, 31];
//! let rhs = [9, 10, 11];
//! let mut output = [0; 3];
//! modulus.reduce_mul_slice_to(&lhs, &rhs, &mut output);
//! assert_eq!(output, [11, 6, 50]);
//! ```

pub use primus_integer as integer;
pub use primus_reduce as reduce;

pub mod common;

mod barrett;
mod compact;
mod config;

mod modulus_switch;
mod native;
mod power_of_two;
mod uint;

#[cfg(feature = "derive")]
pub use primus_barrett_derive::Barrett;

pub use barrett::BarrettModulus;
pub use compact::CompactModulus;
pub use config::{ModulusConfig, ModulusConfigError};

pub use native::NativeModulus;
pub use power_of_two::PowOf2Modulus;
pub use uint::UintModulus;

#[cfg(feature = "simd")]
pub use barrett::{
    SimdBarrettModulus, simd_reduce_dot_product as barrett_simd_reduce_dot_product,
    simd_reduce_dot_product_signed as barrett_simd_reduce_dot_product_signed,
};

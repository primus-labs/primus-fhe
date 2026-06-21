#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

//! Concrete modulus types implementing the [`primus_reduce`] traits.
//!
//! | Type | Reduction | Use case |
//! |------|-----------|----------|
//! | [`NativeModulus`] | Wrapping arithmetic (mod 2^BITS) | Native integer overflow |
//! | [`PowOf2Modulus`] | Bitwise mask (mod 2^k) | Explicit power-of-two |
//! | [`BarrettModulus`] | Barrett reduction (`m < 2^{BITS-1}`) | General prime modulus |
//! | [`CompactModulus`] | Wrapping add/sub (`m < 2^{BITS-2}`) | Optimized basic ops |
//! | [`UintModulus`] | Compare-and-subtract (any m) | Fallback |

pub use primus_integer as integer;
pub use primus_reduce as reduce;

pub mod common;

mod barrett;
mod compact;

mod native;
mod power_of_two;
mod uint;

pub use barrett::BarrettModulus;
pub use compact::CompactModulus;

pub use native::NativeModulus;
pub use power_of_two::PowOf2Modulus;
pub use uint::UintModulus;

#[cfg(feature = "simd")]
pub use barrett::{SimdBarrettModulus, simd_reduce_dot_product};

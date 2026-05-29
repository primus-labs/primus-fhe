mod primitive;
pub mod slice;

#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

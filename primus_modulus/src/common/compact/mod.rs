mod primitive;
pub mod slice;

#[cfg(feature = "simd")]
pub mod simd;

pub use primitive::*;

pub const DOT_PRODUCT_INNER_CHUNK: usize = 16;

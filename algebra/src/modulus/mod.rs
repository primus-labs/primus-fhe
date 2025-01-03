//! Defines some moduli.

mod barrett;
mod native;
mod powof2;
mod shoup;

pub use barrett::BarrettModulus;
pub use native::NativeModulus;
pub use powof2::PowOf2Modulus;
pub use shoup::ShoupFactor;

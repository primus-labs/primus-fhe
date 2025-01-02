mod barrett;
// mod fast;
mod native;
mod powof2;
mod shoup;

pub use barrett::BarrettModulus;
// pub use fast::FastModulus;
pub use native::NativeModulus;
pub use powof2::PowOf2Modulus;
pub use shoup::ShoupFactor;

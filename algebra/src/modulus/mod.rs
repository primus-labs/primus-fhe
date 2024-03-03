//! This module implements some functions and methods for
//! modular arithmetic.

mod barrett;
mod powof2;
mod shoup;

pub use barrett::BarrettModulus;
pub use powof2::PowOf2Modulus;
pub use shoup::ShoupFactor;

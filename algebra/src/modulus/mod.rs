//! This module implements some functions and methods for
//! modular arithmetic.

pub mod baby_bear;
mod barrett;
pub mod goldilocks;
mod powof2;
mod shoup;

pub use baby_bear::BabyBearModulus;
pub use barrett::BarrettModulus;
pub use goldilocks::GoldilocksModulus;
pub use powof2::PowOf2Modulus;
pub use shoup::ShoupFactor;

//! This module implements some functions and methods for
//! modular arithmetic.

mod barrett;
mod powof2;

pub use barrett::{BarrettModulus, MulReduceFactor};
pub use powof2::PowOf2Modulus;

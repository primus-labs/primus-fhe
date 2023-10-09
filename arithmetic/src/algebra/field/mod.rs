use num_traits::Inv;

use super::ring::CommutativeRing;

mod fp;

pub use fp::Fp;

pub trait Field: CommutativeRing + Inv<Output = Self> {}

impl<F> Field for F where F: CommutativeRing + Inv<Output = Self> {}

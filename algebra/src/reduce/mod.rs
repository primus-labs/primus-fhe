//! This module defines some traits for modular arithmetic.

mod lazy_ops;
mod ops;

mod macros;

pub use lazy_ops::*;
use num_traits::{ConstOne, ConstZero};
pub use ops::*;

/// A helper trait to get the modulus of the field.
pub trait ModulusConfig {
    /// Modulus type
    type Modulus;

    /// The modulus of the field.
    const MODULUS: Self::Modulus;

    /// Get the modulus of the field.
    #[inline]
    fn modulus() -> Self::Modulus {
        Self::MODULUS
    }
}

///
pub trait AddReduceOps<Modulus>
where
    Self:
        Copy + ConstZero + AddReduce<Modulus, Self, Output = Self> + AddReduceAssign<Modulus, Self>,
{
}

impl<T, Modulus> AddReduceOps<Modulus> for T where
    T: Copy + ConstZero + AddReduce<Modulus, Self, Output = Self> + AddReduceAssign<Modulus, Self>
{
}

///
pub trait SubReduceOps<Modulus>
where
    Self:
        Copy + ConstZero + SubReduce<Modulus, Self, Output = Self> + SubReduceAssign<Modulus, Self>,
{
}

impl<T, Modulus> SubReduceOps<Modulus> for T where
    T: Copy + ConstZero + SubReduce<Modulus, Self, Output = Self> + SubReduceAssign<Modulus, Self>
{
}

///
pub trait MulReduceOps<Modulus>
where
    Self:
        Copy + ConstOne + MulReduce<Modulus, Self, Output = Self> + MulReduceAssign<Modulus, Self>,
{
}

impl<T, Modulus> MulReduceOps<Modulus> for T where
    T: Copy + ConstOne + MulReduce<Modulus, Self, Output = Self> + MulReduceAssign<Modulus, Self>
{
}

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

mod fp;

pub use fp::Fp;

pub trait Field:
    Sized
    + PartialEq
    + PartialOrd
    + Zero
    + One
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + DivAssign
    + Neg<Output = Self>
    + Inv<Output = Self>
{
    fn has_impl_field_traits() -> bool;
}

impl<F> Field for F
where
    F: Sized
        + PartialEq
        + PartialOrd
        + Zero
        + One
        + Add<Self, Output = Self>
        + Sub<Self, Output = Self>
        + Mul<Self, Output = Self>
        + Div<Self, Output = Self>
        + AddAssign
        + SubAssign
        + MulAssign
        + DivAssign
        + Neg<Output = Self>
        + Inv<Output = Self>,
{
    fn has_impl_field_traits() -> bool {
        true
    }
}

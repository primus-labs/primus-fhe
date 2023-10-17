//! This place defimes some concrete implement of the algebra.

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Zero};

pub mod prime_fields;

/// A simple math field trait
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
    /// Check the field is well-defined or not.
    fn check_field_trait() -> bool {
        true
    }
}


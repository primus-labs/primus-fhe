//! This place defimes some concrete implement of the algebra.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Pow, Zero};

pub mod prime_fields;

/// A simple math field trait
pub trait Field:
    Sized
    + Copy
    + Clone
    + Debug
    + Display
    + Default
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Zero
    + One
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + DivAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + for<'a> DivAssign<&'a Self>
    + Neg<Output = Self>
    + Inv<Output = Self>
    + Pow<u8, Output = Self>
    + Pow<u16, Output = Self>
    + Pow<u32, Output = Self>
    + Pow<u64, Output = Self>
    + Pow<u128, Output = Self>
{
    /// Returns `self + self`.
    #[inline]
    fn double(&self) -> Self {
        *self + self
    }

    /// Doubles `self` in place.
    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self += *self;
        self
    }

    /// Negates `self` in place.
    #[inline]
    fn neg_in_place(&mut self) -> &mut Self {
        *self = -*self;
        self
    }

    /// Returns `self * self`.
    #[inline]
    fn square(&self) -> Self {
        *self * self
    }

    /// Squares `self` in place.
    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        *self *= *self;
        self
    }

    /// Computes the multiplicative inverse of `self` if `self` is nonzero.
    #[inline]
    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.inv())
        }
    }

    /// If `self.inverse().is_none()`, this just returns `None`. Otherwise, it sets
    /// `self` to `self.inverse().unwrap()`.
    #[inline]
    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if self.is_zero() {
            None
        } else {
            *self = self.inv();
            Some(self)
        }
    }
}

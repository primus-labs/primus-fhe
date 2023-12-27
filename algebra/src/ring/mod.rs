//! This place defines some concrete implement of ring of the algebra.

use std::fmt::{Debug, Display};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{One, Pow, PrimInt, Zero};

use crate::field::Random;
use crate::RoundedDiv;

/// A trait defining the algebraic structure of a mathematical ring.
///
/// This trait encapsulates the properties and operations that define a ring in algebra.
/// Rings are sets equipped with two binary operations: addition and multiplication,
/// satisfying certain axioms. In addition to these, this trait provides additional
/// utility methods and traits to work with ring elements in a Rust program.
///
/// The `Ring` trait extends various Rust standard library traits to ensure ring elements
/// can be copied, cloned, debugged, displayed, compared, and have a sense of 'zero' and 'one'.
/// Additionally, it supports standard arithmetic operations like addition, subtraction,
/// multiplication, and exponentiation, as well as assignment versions of these operations.
///
/// Types implementing `Ring` must provide implementations for scalar multiplication,
/// negation, doubling, and squaring operations, both as returning new instances and
/// mutating the current instance in place.
///
/// Implementing this trait enables types to be used within mathematical constructs and
/// algorithms that require ring properties, such as many cryptographic systems, coding theory,
/// and computational number theory.
pub trait Ring:
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
    + Zero
    + One
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + Neg<Output = Self>
    + Pow<Self::Order, Output = Self>
    + From<Self::Inner>
{
    /// The inner type of this ring.
    type Inner: Debug + PrimInt + RoundedDiv<Output = Self::Inner>;

    /// The type of the ring's order.
    type Order: Copy;

    /// Creates a new instance.
    fn new(value: Self::Inner) -> Self;

    /// Return inner value
    fn inner(self) -> Self::Inner;

    /// cast inner to [`usize`]
    fn cast_into_usize(self) -> usize;

    /// cast from [`usize`]
    fn cast_from_usize(value: usize) -> Self;

    /// cast inner to [`f64`]
    fn as_f64(self) -> f64;

    /// cast from [`f64`]
    fn from_f64(value: f64) -> Self;

    /// Returns the modulus.
    fn modulus() -> Self::Inner;

    /// Returns the order of the ring.
    fn order() -> Self::Order;

    /// Get the length of decompose vec.
    fn decompose_len(basis: usize) -> usize;

    /// Decompose `self` according to `basis`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose(&self, basis: usize) -> Vec<Self>;

    /// Return `self * scalar`.
    fn mul_scalar(&self, scalar: Self::Inner) -> Self;

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
}

/// A trait combine [`Ring`] with random property.
pub trait RandomRing: Ring + Random {}

impl<R> RandomRing for R where R: Ring + Random {}

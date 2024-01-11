//! This place defines some concrete implement of ring of the algebra.

use std::fmt::{Debug, Display};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{One, Pow, PrimInt, Zero};

use crate::{Basis, Random, RoundedDiv};

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
    + Send
    + Sync
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
    type Inner: Debug + PrimInt + RoundedDiv<Output = Self::Inner> + Send + Sync;

    /// The type of the ring's order.
    type Order: Copy;

    /// 1
    const ONE: Self;

    /// 0
    const ZERO: Self;

    /// -1
    const NEG_ONE: Self;

    /// q/8
    const Q_DIV_8: Self;

    /// 3q/8
    const Q3_DIV_8: Self;

    /// 7q/8
    const Q7_DIV_8: Self;

    /// -q/8
    const NRG_Q_DIV_8: Self;

    /// 4
    const FOUR_INNER: Self::Inner;

    /// q
    const MODULUS_F64: f64;

    /// Creates a new instance.
    fn new(value: Self::Inner) -> Self;

    /// power of 2
    fn pow_of_two(pow: u32) -> Self;

    /// mask
    fn mask(bits: u32) -> Self::Inner;

    /// Return inner value
    fn inner(self) -> Self::Inner;

    /// cast self to [`usize`]
    fn cast_into_usize(self) -> usize;

    /// cast from [`usize`]
    fn cast_from_usize(value: usize) -> Self;

    /// cast inner to [`f64`]
    fn to_f64(self) -> f64;

    /// cast from [`f64`]
    fn from_f64(value: f64) -> Self;

    /// Returns the modulus value.
    fn modulus_value() -> Self::Inner;

    /// Returns the order of the ring.
    fn order() -> Self::Order;

    /// Get the length of decompose vec.
    fn decompose_len(basis: Self::Inner) -> usize;

    /// Decompose `self` according to `basis`,
    /// return the decomposed vector.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose(self, basis: Basis<Self>) -> Vec<Self>;

    /// Decompose `self` according to `basis`,
    /// put the decomposed result into `dst`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_at(self, basis: Basis<Self>, dst: &mut [Self]);

    /// Decompose `self` according to `basis`'s `mask` and `bits`,
    /// return the least significant decomposed part.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_lsb_bits(&mut self, mask: Self::Inner, bits: u32) -> Self;

    /// Decompose `self` according to `basis`'s `mask` and `bits`,
    /// put the least significant decomposed part into `dst`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_lsb_bits_at(&mut self, dst: &mut Self, mask: Self::Inner, bits: u32);

    /// Return `self * scalar`.
    fn mul_scalar(self, scalar: Self::Inner) -> Self;

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

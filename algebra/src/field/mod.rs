//! This place defines some concrete implement of field of the algebra.

use std::fmt::{Debug, Display};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Pow, PrimInt, Zero};

use crate::{Basis, Random};

mod ntt_fields;
mod prime_fields;

pub use ntt_fields::NTTField;
pub use prime_fields::PrimeField;

/// A trait defining the algebraic structure of a mathematical field.
///
/// Fields are algebraic structures with two operations: addition and multiplication,
/// where every nonzero element has a multiplicative inverse. In a field, division
/// by any non-zero element is possible and every element except zero has an inverse.
///
/// The [`Field`] trait extends various Rust standard library traits to ensure field elements
/// can be copied, cloned, debugged, displayed, compared, and have a sense of 'zero' and 'one'.
/// Additionally, it supports standard arithmetic operations like addition, subtraction,
/// multiplication, division, and exponentiation, as well as assignment versions of these operations.
///
/// Types implementing [`Field`] also provide implementations for scalar multiplication,
/// negation, doubling, and squaring operations, both as returning new instances and
/// mutating the current instance in place.
///
/// Implementing this trait enables types to be used within mathematical constructs and
/// algorithms that require field properties, such as many cryptographic systems, coding theory,
/// and computational number theory.
pub trait Field:
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
    + Pow<Self::Order, Output = Self>
    + From<Self::Inner>
{
    /// The inner type of this field.
    type Inner: Debug + PrimInt + Send + Sync;

    /// The type of the field's order.
    type Order: Copy;

    /// 1
    const ONE: Self;

    /// 0
    const ZERO: Self;

    /// -1
    const NEG_ONE: Self;

    /// 1
    const ONE_INNER: Self::Inner;

    /// 0
    const ZERO_INNER: Self::Inner;

    /// q/8
    const Q_DIV_8: Self;

    /// -q/8
    const NRG_Q_DIV_8: Self;

    /// q
    const MODULUS_F64: f64;

    /// Creates a new instance.
    fn new(value: Self::Inner) -> Self;

    /// mask, return a number with `bits` 1s.
    fn mask(bits: u32) -> Self::Inner;

    /// Return inner value.
    fn inner(self) -> Self::Inner;

    /// cast self to [`usize`].
    fn cast_into_usize(self) -> usize;

    /// cast from [`usize`].
    fn cast_from_usize(value: usize) -> Self;

    /// cast inner to [`f64`].
    fn to_f64(self) -> f64;

    /// cast from [`f64`].
    fn from_f64(value: f64) -> Self;

    /// Returns the modulus value.
    fn modulus_value() -> Self::Inner;

    /// Returns the order of the field.
    fn order() -> Self::Order;

    /// Get the length of decompose vector.
    fn decompose_len(basis: Self::Inner) -> usize;

    /// Decompose `self` according to `basis`,
    /// return the decomposed vector.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose(self, basis: Basis<Self>) -> Vec<Self>;

    /// Decompose `self` according to `basis`,
    /// put the decomposed result into `destination`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_at(self, basis: Basis<Self>, destination: &mut [Self]);

    /// Decompose `self` according to `basis`'s `mask` and `bits`,
    /// return the least significant decomposed part.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_lsb_bits(&mut self, mask: Self::Inner, bits: u32) -> Self;

    /// Decompose `self` according to `basis`'s `mask` and `bits`,
    /// put the least significant decomposed part into `destination`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Inner, bits: u32);

    /// Return `self * scalar`.
    fn mul_scalar(self, scalar: Self::Inner) -> Self;

    /// Returns `self + self`.
    #[inline]
    fn double(self) -> Self {
        self + self
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
    fn square(self) -> Self {
        self * self
    }

    /// Squares `self` in place.
    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        *self *= *self;
        self
    }

    /// Performs `self + a * b`.
    fn add_mul(self, a: Self, b: Self) -> Self;

    /// Performs `self * a + b`.
    fn mul_add(self, a: Self, b: Self) -> Self;

    /// Performs `self = self + a * b`.
    fn add_mul_assign(&mut self, a: Self, b: Self);

    /// Performs `self = self * a + b`.
    fn mul_add_assign(&mut self, a: Self, b: Self);

    /// Computes the multiplicative inverse of `self` if `self` is nonzero.
    #[inline]
    fn inverse(self) -> Option<Self> {
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

/// A trait combine [`NTTField`] with random property.
pub trait RandomNTTField: NTTField + Random {}

impl<F> RandomNTTField for F where F: NTTField + Random {}

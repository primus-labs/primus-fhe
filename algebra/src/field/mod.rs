//! This place defines some concrete implement of field of the algebra.

use std::fmt::{Debug, Display};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{Inv, One, Pow, PrimInt, Zero};
use serde::Serialize;

use crate::random::UniformBase;
use crate::{AsFrom, AsInto, Basis, Widening, WrappingOps};

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
    + Serialize
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
{
    /// The inner type of this field.
    type Value: Debug
        + Send
        + Sync
        + PrimInt
        + Widening
        + WrappingOps
        + Into<u64>
        + AsFrom<u32>
        + AsInto<f64>
        + AsFrom<f64>
        + UniformBase;

    /// The type of the field's order.
    type Order: Copy;

    /// 1
    const ONE: Self;

    /// 0
    const ZERO: Self;

    /// -1
    const NEG_ONE: Self;

    /// q
    const MODULUS_VALUE: Self::Value;

    /// 2q
    const TWICE_MODULUS_VALUE: Self::Value;

    /// Creates a new instance.
    fn new(value: Self::Value) -> Self;

    /// Creates and checks a new instance.
    fn checked_new(value: Self::Value) -> Self;

    /// Gets inner value.
    fn get(self) -> Self::Value;

    /// Resets inner value.
    fn set(&mut self, value: Self::Value);

    /// Resets and checks inner value.
    fn checked_set(&mut self, value: Self::Value);

    /// Return `self * scalar`.
    fn mul_scalar(self, scalar: Self::Value) -> Self;

    /// Performs `self + a * b`.
    fn add_mul(self, a: Self, b: Self) -> Self;

    /// Performs `self = self + a * b`.
    fn add_mul_assign(&mut self, a: Self, b: Self);

    /// Performs `self * rhs`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    fn mul_fast(self, rhs: Self) -> Self;

    /// Performs `self *= rhs`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    fn mul_assign_fast(&mut self, rhs: Self);

    /// Performs `self + a * b`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    fn add_mul_fast(self, a: Self, b: Self) -> Self;

    /// Performs `self = self + a * b`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    fn add_mul_assign_fast(&mut self, a: Self, b: Self);

    /// mask, return a number with `bits` 1s.
    fn mask(bits: u32) -> Self::Value;

    /// Get the length of decompose vector.
    fn decompose_len(basis: Self::Value) -> usize;

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
    fn decompose_lsb_bits(&mut self, mask: Self::Value, bits: u32) -> Self;

    /// Decompose `self` according to `basis`'s `mask` and `bits`,
    /// put the least significant decomposed part into `destination`.
    ///
    /// Now we focus on power-of-two basis.
    fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Value, bits: u32);
}

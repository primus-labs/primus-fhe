//! This place defines some concrete implement of field of the algebra.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_traits::{ConstOne, ConstZero, Inv, Pow};
use rand::{CryptoRng, Rng};

use crate::random::UniformBase;
use crate::{AsFrom, AsInto, Basis, ConstNegOne, Primitive, WideningMul, WrappingNeg};

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
    + ConstZero
    + ConstOne
    + Hash
    + ConstNegOne
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
    type Value: Primitive;

    /// The type of the field's order.
    type Order: Copy;

    /// q
    const MODULUS_VALUE: Self::Value;

    /// convert values into field element
    fn new(value: Self::Value) -> Self;

    /// generate a random element.
    fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let range = <Self::Value as UniformBase>::Sample::as_from(Self::MODULUS_VALUE);
        let thresh = range.wrapping_neg() % range;

        let hi = loop {
            let (lo, hi) = <Self::Value as UniformBase>::gen_sample(rng).widening_mul(range);
            if lo >= thresh {
                break hi;
            }
        };

        Self::new(hi.as_into())
    }

    /// Gets inner value.
    fn value(self) -> Self::Value;
}

/// A trait defined for decomposable field, this is mainly for base field in FHE.
pub trait DecomposableField: Field {
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

/// A trait defined for specific fields used and optimized for FHE.
pub trait FheField: DecomposableField {
    /// Creates a new instance.
    /// Can be overloaded with optimized implementation.
    #[inline]
    fn lazy_new(value: Self::Value) -> Self {
        Self::new(value)
    }

    /// Performs `self + a * b`.
    /// Can be overloaded with optimized implementation.
    #[inline]
    fn add_mul(self, a: Self, b: Self) -> Self {
        self + a * b
    }

    /// Performs `self = self + a * b`.
    #[inline]
    fn add_mul_assign(&mut self, a: Self, b: Self) {
        *self = self.add_mul(a, b);
    }

    /// Performs `self * rhs`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    /// Can be overloaded with optimized implementation.
    #[inline]
    fn mul_fast(self, rhs: Self) -> Self {
        self * rhs
    }

    /// Performs `self *= rhs`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    #[inline]
    fn mul_assign_fast(&mut self, rhs: Self) {
        *self = self.mul_fast(rhs);
    }

    /// Performs `self + a * b`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    #[inline]
    fn add_mul_fast(self, a: Self, b: Self) -> Self {
        self + a * b
    }

    /// Performs `self = self + a * b`.
    ///
    /// The result is in [0, 2*modulus) for some special modulus, such as `BarrettModulus`,
    /// and falling back to [0, modulus) for normal case.
    #[inline]
    fn add_mul_assign_fast(&mut self, a: Self, b: Self) {
        *self = self.add_mul_fast(a, b);
    }
}

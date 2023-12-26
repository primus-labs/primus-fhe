//! This place defines some concrete implement of field of the algebra.

use std::ops::{Div, DivAssign};

use num_traits::Inv;

use crate::ring::Ring;

mod distribution;
mod ntt_fields;
mod prime_fields;

pub use distribution::Random;
pub use ntt_fields::NTTField;
pub use prime_fields::{MulFactor, PrimeField};

/// A helper trait to get the modulus of the ring or field.
pub trait BarrettConfig {
    /// Barrett Modulus type
    type BarrettModulus;

    /// The modulus of the ring or field.
    const BARRETT_MODULUS: Self::BarrettModulus;

    /// Get the barrett modulus of the ring or field.
    #[inline]
    fn barrett_modulus() -> Self::BarrettModulus {
        Self::BARRETT_MODULUS
    }
}

/// A trait that extends the algebraic structure of a `Ring` to a `Field`.
///
/// Fields are algebraic structures with two operations: addition and multiplication,
/// where every nonzero element has a multiplicative inverse. This trait builds upon
/// the `Ring` trait, adding division and multiplicative inverse operations, thereby
/// extending the ring into a field. In a field, division by any non-zero element is
/// possible and every element except zero has an inverse.
///
/// The `Field` trait includes division and division assignment operations, including
/// their reference-based variants. This allows for division of field elements in an
/// ergonomic manner consistent with Rust's ownership and borrowing principles.
pub trait Field:
    Ring
    + Div<Self, Output = Self>
    + DivAssign<Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> DivAssign<&'a Self>
    + Inv<Output = Self>
{
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

/// A trait combine [`NTTField`] with random property.
pub trait RandomNTTField: NTTField + Random {}

impl<F> RandomNTTField for F where F: NTTField + Random {}

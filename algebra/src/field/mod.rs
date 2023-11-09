//! This place defines some concrete implement of field of the algebra.

use std::ops::{Div, DivAssign};

use num_traits::Inv;

mod fp32;
pub mod ntt_fields;
pub mod prime_fields;

pub use fp32::{BarrettConfig, Fp32};
pub use ntt_fields::NTTField;
pub use prime_fields::PrimeField;

use crate::ring::Ring;

/// A simple math field trait
pub trait Field:
    Ring
    + Div<Self, Output = Self>
    + DivAssign<Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> DivAssign<&'a Self>
    + Inv<Output = Self>
{
    /// The type of the modulus.
    type Modulus;

    /// Returns the modulus.
    fn modulus() -> Self::Modulus;

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

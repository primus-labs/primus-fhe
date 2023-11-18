//! This place defines some concrete implement of field of the algebra.

use std::ops::{Div, DivAssign};

use num_traits::Inv;

mod distribution;
mod fp32;
pub mod ntt_fields;
pub mod prime_fields;

pub use distribution::FieldDistribution;
pub use fp32::{BarrettConfig, Fp32, NormalFp32, TernaryFp32};
pub use ntt_fields::NTTField;
pub use prime_fields::PrimeField;

use crate::ring::Ring;

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
///
/// Types implementing `Field` must also provide a method to retrieve the modulus,
/// which typically defines the size of the finite field.
///
/// Implementing this trait enables the use of types in contexts that require field properties,
/// such as certain cryptographic protocols, error-correcting codes, and other mathematical
/// applications where division and inverses within a finite set are necessary operations.
pub trait Field:
    Ring
    + Div<Self, Output = Self>
    + DivAssign<Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> DivAssign<&'a Self>
    + Inv<Output = Self>
{
    /// The type of the modulus.
    type Modulus: Clone;

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

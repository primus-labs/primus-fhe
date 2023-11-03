//! This place defines some concrete implement of the field.

mod fp32;

pub use fp32::{BarrettConfig, Fp32};

use super::Field;

/// Define `PrimeField` trait
pub trait PrimeField: Field {
    /// Check [`Self`] is a prime field.
    fn is_prime_field() -> bool;
}

/// A factor for multiply many times
#[derive(Clone, Copy, Default)]
pub struct MulFactor<F> {
    value: F,
    quotient: F,
}

impl<F: Copy> MulFactor<F> {
    /// Returns the value of this [`MulFactor<F>`].
    #[inline]
    pub fn value(&self) -> F {
        self.value
    }

    /// Returns the quotient of this [`MulFactor<F>`].
    #[inline]
    pub fn quotient(&self) -> F {
        self.quotient
    }
}

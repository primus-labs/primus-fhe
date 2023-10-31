//! This place defines some concrete implement of the field.

mod fp32;

pub use fp32::{BarrettConfig, Fp32, MulFactor, RootFactor};

use super::Field;

/// Define `PrimeField` trait
pub trait PrimeField: Field {
    /// Check [`Self`] is a prime field.
    fn is_prime_field() -> bool;
}

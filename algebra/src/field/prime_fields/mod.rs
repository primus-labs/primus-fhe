//! This place defines some concrete implement of the field.

mod fp32;

pub use fp32::{BarrettConfig, Fp32};

use super::Field;

/// Define `PrimeField` trait
pub trait PrimeField: Field {}

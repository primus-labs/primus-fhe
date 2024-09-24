//! This module defines some traits for modular arithmetic.

mod lazy_ops;
mod ops;

mod macros;

pub use lazy_ops::*;
pub use ops::*;

/// A helper trait to get the modulus of the field.
pub trait ModulusConfig {
    /// Modulus type
    type Modulus;

    /// The modulus of the field.
    const MODULUS: Self::Modulus;

    /// Get the modulus of the field.
    #[inline]
    fn modulus() -> Self::Modulus {
        Self::MODULUS
    }
}

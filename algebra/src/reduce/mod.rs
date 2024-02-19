//! This module defines some traits for modular arithmetic.

mod ops;

mod primitive;

pub use ops::*;

/// A helper trait to get the modulus of the field.
pub trait ModulusConfig {
    /// Barrett Modulus type
    type Modulus;

    /// The modulus of the field.
    const MODULUS: Self::Modulus;

    /// Get the barrett modulus of the field.
    #[inline]
    fn modulus() -> Self::Modulus {
        Self::MODULUS
    }
}

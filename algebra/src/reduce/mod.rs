//! This module defines some traits for modular arithmetic.

mod ops;

mod primitive;

pub use ops::*;

/// A helper trait to get the modulus of the ring or field.
pub trait ModulusConfig {
    /// Barrett Modulus type
    type Modulus;

    /// The modulus of the ring or field.
    const MODULUS: Self::Modulus;

    /// Get the barrett modulus of the ring or field.
    #[inline]
    fn modulus() -> Self::Modulus {
        Self::MODULUS
    }
}

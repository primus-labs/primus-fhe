use core::fmt::Debug;

use thiserror::Error;

/// Error type for modular reduction operations that can fail.
///
/// Currently only covers the case where a multiplicative inverse does not
/// exist (the value and modulus are not coprime).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ReduceError<T> {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("value {value:?} has no inverse modulo {modulus:?}")]
    NoInverse {
        /// The value being inverted.
        value: T,
        /// The modulus.
        modulus: T,
    },
    /// Error that occurs when the given value has no inverse element with an
    /// implicit native modulus that cannot be represented in `T`.
    #[error("value {value:?} has no inverse modulo the implicit native modulus")]
    NoInverseImplicitModulus {
        /// The value being inverted.
        value: T,
    },
}

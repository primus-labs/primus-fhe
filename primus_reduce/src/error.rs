use core::fmt::Debug;

use thiserror::Error;

/// Error type for modular reduction operations that can fail.
///
/// Currently only covers the case where a multiplicative inverse does not
/// exist (the value and modulus are not coprime).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ReduceError<T> {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("Value {value:?} has no inverse element with the modulus {modulus:?}!")]
    NoInverse {
        /// The value being inverted.
        value: T,
        /// The modulus.
        modulus: T,
    },
    /// Error that occurs when a value at a specific index has no inverse element.
    #[error(
        "Value at index {index} ({value:?}) has no inverse element with the modulus {modulus:?}!"
    )]
    NoInverseAtIndex {
        /// The zero-based index of the failing element.
        index: usize,
        /// The value being inverted.
        value: T,
        /// The modulus.
        modulus: T,
    },
}

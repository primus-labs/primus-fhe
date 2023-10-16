//! This module defines some errors that
//! may occur during the execution of the library.

use thiserror::Error;

/// Errors that may occur when it comes to Modular operations.
#[derive(Error, Debug)]
pub enum ModuloError {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("Value {value} has no inverse element with the modulus {modulus}!")]
    NoModuloInverse {
        /// The value being inverted.
        value: String,
        /// The modulus.
        modulus: String,
    },
    /// Error that occurs when user ask to generate a modulus with invalid bit count.
    #[error("The bit count of desired coeff modulus is not valid")]
    BitCountError,
}

//! This module defines some errors that
//! may occur during the execution of the library.

use thiserror::Error;

/// Errors that may occur.
#[derive(Error, Debug)]
pub enum AlgebraError {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("Value {value} has no inverse element with the modulus {modulus}!")]
    NoReduceInverse {
        /// The value being inverted.
        value: String,
        /// The modulus.
        modulus: String,
    },
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("There is no primitive root with the degree {degree} and the modulus {modulus}!")]
    NoPrimitiveRoot {
        /// the degree for the primitive root
        degree: String,
        /// The modulus.
        modulus: String,
    },
    /// Error that occurs when user ask to generate a modulus with invalid bit count.
    #[error("The bit count of desired coeff modulus is not valid")]
    BitCountError,
    /// Error that occurs when fails to generate the ntt table.
    #[error("Fail to generate the desired ntt table.")]
    NTTTableError,
    /// Error that occurs when fails to generate the distribution.
    #[error("Fail to generate the desired distribution.")]
    DistributionError,
}

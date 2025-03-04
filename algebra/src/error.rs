//! This module defines some errors that
//! may occur during the execution of the library.

use std::fmt::Debug;

use thiserror::Error;

/// Errors that may occur.
#[derive(Error, Debug)]
pub enum AlgebraError {
    /// Error that occurs when the given value has no inverse element with the given modulus.
    #[error("Value {value:?} has no inverse element with the modulus {modulus:?}!")]
    NoInverse {
        /// The value being inverted.
        value: Box<dyn Debug>,
        /// The modulus.
        modulus: Box<dyn Debug>,
    },
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("There is no primitive root with the degree {degree:?} and the modulus {modulus:?}!")]
    NoPrimitiveRoot {
        /// The degree for the primitive root
        degree: Box<dyn Debug>,
        /// The modulus.
        modulus: Box<dyn Debug>,
    },
    /// Error that occurs when user ask to generate a modulus with invalid bit count.
    #[error("The bit count of desired coeff modulus is not valid")]
    BitCountErr,
    /// Error that occurs when fails to generate the ntt table.
    #[error("Fail to generate the desired ntt table.")]
    NttTableErr,
    /// Error that occurs when fails to generate the distribution.
    #[error("Fail to generate the desired distribution.")]
    DistributionErr,
    /// Error that occurs when fails to convert the degree into desired type.
    #[error("out of range integral type conversion attempted: {degree} -> {modulus:?}")]
    DegreeConversionErr {
        /// degree
        degree: usize,
        /// modulus
        modulus: Box<dyn Debug>,
    },
    /// Error that occurs when the degree is too large.
    #[error("degree should less than modulus: {degree} >= {modulus:?}")]
    TooLargeDegreeErr {
        /// degree
        degree: usize,
        /// modulus
        modulus: Box<dyn Debug>,
    },
}

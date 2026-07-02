use std::fmt::Debug;

use thiserror::Error;

/// Errors that may occur.
#[derive(Error, Debug)]
pub enum NttError<T> {
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("There is no primitive root with the degree {degree:?} and the modulus {modulus:?}!")]
    NoPrimitiveRoot {
        /// The degree for the primitive root
        degree: T,
        /// The modulus.
        modulus: T,
    },
    /// Error that occurs when fails to convert the degree into desired type.
    #[error("out of range integral type conversion attempted: {degree} -> {modulus:?}")]
    DegreeConversionErr {
        /// degree
        degree: usize,
        /// modulus
        modulus: T,
    },
    /// Error that occurs when the degree is too large.
    #[error("degree should less than modulus: {degree} >= {modulus:?}")]
    DegreeTooLarge {
        /// degree
        degree: usize,
        /// modulus
        modulus: T,
    },
    /// Error that occurs when fails to generate the ntt table.
    #[error("Fail to generate the desired ntt table.")]
    NttTableErr,
}

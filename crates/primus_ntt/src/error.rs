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

    /// Error that occurs when the modulus is too large for the selected
    /// fast path (e.g. `q >= 2^30` for `U32NttTable` or `q >= 2^62` for
    /// `U64NttTable`).
    #[error(
        "modulus {modulus} is too large for this NTT table (max {max_bits}-bit supported; \
         use the generic `UintNttTable` as a fallback)"
    )]
    ModulusTooLarge {
        /// The modulus value.
        modulus: T,
        /// The maximum supported bit-width for this table type.
        max_bits: u32,
    },
}

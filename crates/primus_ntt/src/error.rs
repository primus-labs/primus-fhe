use std::fmt::Debug;

use thiserror::Error;

/// Invalid NTT table geometry, coefficient range or root of unity.
#[derive(Error, Debug)]
pub enum NttError<T> {
    /// A DCRT transform was requested without any component modulus.
    #[error("DCRT modulus list must be non-empty")]
    EmptyModuli,
    /// The combined coefficient count for a DCRT table does not fit `usize`.
    #[error("DCRT polynomial length overflow")]
    CrtPolynomialLengthOverflow,
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("no primitive root of degree {degree:?} exists modulo {modulus:?}")]
    NoPrimitiveRoot {
        /// The requested root order (`2N` for an NTT table of length `N`).
        degree: T,
        /// The modulus.
        modulus: T,
    },
    /// The required root order `2N` does not fit the table's coefficient type.
    #[error(
        "root degree {degree} is not representable by the coefficient type for modulus {modulus:?}"
    )]
    DegreeNotRepresentable {
        /// The required root order `2N`, not the polynomial length `N`.
        degree: usize,
        /// The modulus.
        modulus: T,
    },
    /// The generic table's polynomial length `N` is not less than the modulus.
    #[error("polynomial length must be less than modulus: {degree} >= {modulus:?}")]
    DegreeTooLarge {
        /// The polynomial length `N`, not the root order `2N`.
        degree: usize,
        /// The modulus.
        modulus: T,
    },
    /// Error that occurs when the modulus is too large for lazy NTT arithmetic.
    #[error("modulus {modulus} is too large for this NTT table (requires modulus < 2^{max_bits})")]
    ModulusTooLarge {
        /// The modulus value.
        modulus: T,
        /// The maximum supported bit-width for this table type.
        max_bits: u32,
    },
}

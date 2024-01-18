use thiserror::Error;

/// Errors that may occur.
#[derive(Error, Debug)]
pub enum FHEError {
    /// Error that occurs when the given lwe dimension is not valid.
    #[error("LWE dimension {0} is not valid!")]
    LweDimensionUnValid(
        /// The value being inverted.
        usize,
    ),
    /// Error that occurs when the given rlwe dimension is not valid.
    #[error("RLWE dimension {0} is not valid!")]
    RlweDimensionUnValid(
        /// The value being inverted.
        usize,
    ),
    /// Error that occurs when the given lwe modulus
    /// is not compatible with rlwe dimension.
    #[error("LWE modulus {lwe_modulus} is not compatible with RLWE dimension {rlwe_dimension}!")]
    LweModulusRlweDimensionNotCompatible {
        /// LWE modulus
        lwe_modulus: usize,
        /// RLWE dimension
        rlwe_dimension: usize,
    },
    /// Error that occurs when the given rlwe modulus
    /// is not compatible with rlwe dimension.
    #[error("RLWE modulus {rlwe_modulus} is not compatible with RLWE dimension {rlwe_dimension}!")]
    RLweModulusRlweDimensionNotCompatible {
        /// RLWE modulus
        rlwe_modulus: usize,
        /// RLWE dimension
        rlwe_dimension: usize,
    },
}

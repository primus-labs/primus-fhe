/// Errors that may occur.
#[derive(thiserror::Error, Debug)]
pub enum FHECoreError {
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
    /// Error that occurs when the given ntru dimension is not valid.
    #[error("NTRU dimension {0} is not valid!")]
    NtruDimensionUnValid(
        /// The value being inverted.
        usize,
    ),
    /// Error that occurs when the given lwe modulus
    /// is not compatible with ntru dimension.
    #[error("LWE modulus {lwe_modulus} is not compatible with NTRU dimension {ntru_dimension}!")]
    LweModulusNtruDimensionNotCompatible {
        /// LWE modulus
        lwe_modulus: usize,
        /// NTRU dimension
        ntru_dimension: usize,
    },
    /// Error that occurs when the given ntru modulus
    /// is not compatible with ntru dimension.
    #[error("NTRU modulus {ntru_modulus} is not compatible with NTRU dimension {ntru_dimension}!")]
    NtruModulusNtruDimensionNotCompatible {
        /// NTRU modulus
        ntru_modulus: usize,
        /// NTRU dimension
        ntru_dimension: usize,
    },
}

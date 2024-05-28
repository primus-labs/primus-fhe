/// Errors that may occur.
#[derive(thiserror::Error, Debug)]
pub enum FHECoreError {
    /// Error that occurs when the given polynomial modulus dimension of ring is not valid.
    #[error("Polynoomial dimension of Ring is not valid!:{0}")]
    RingDimensionUnValid(
        /// Polynomial dimension of Ring.
        usize,
    ),
    /// Error that occurs when the given lwe modulus
    /// is not compatible with polynomial modulus dimension of ring.
    #[error(
        "LWE modulus {lwe_modulus} is not compatible with polynomial modulus dimension {ring_dimension}!"
    )]
    LweModulusRingDimensionNotCompatible {
        /// LWE modulus.
        lwe_modulus: usize,
        /// Polynomial modulus dimension of ring.
        ring_dimension: usize,
    },
    /// Error that occurs when the given coefficients modulus
    /// is not compatible with polynomial modulus dimension of ring.
    #[error(
        "Coefficients modulus {coeff_modulus} is not compatible with polynomial modulus dimension {ring_dimension}!"
    )]
    RingModulusAndDimensionNotCompatible {
        /// Coefficients modulus of ring.
        coeff_modulus: usize,
        /// Polynomial modulus dimension of ring.
        ring_dimension: usize,
    },
}

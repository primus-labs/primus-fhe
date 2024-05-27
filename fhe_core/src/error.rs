/// Errors that may occur.
#[derive(thiserror::Error, Debug)]
pub enum FHECoreError {
    /// Error that occurs when the given polynomial dimension is not valid.
    #[error("Polynoomial dimension of Ring is not valid!:{0}")]
    RingDimensionUnValid(
        /// Polynomial dimension of Ring.
        usize,
    ),
    /// Error that occurs when the given lwe modulus
    /// is not compatible with polynomial dimension of Ring.
    #[error(
        "LWE modulus {lwe_modulus} is not compatible with polynomial dimension {ring_dimension}!"
    )]
    LweModulusRingDimensionNotCompatible {
        /// LWE modulus.
        lwe_modulus: usize,
        /// Polynomial dimension of Ring.
        ring_dimension: usize,
    },
    /// Error that occurs when the given polynomial modulus
    /// is not compatible with polynomial dimension of Ring.
    #[error(
        "Polynomial modulus {ring_modulus} is not compatible with polynomial dimension {ring_dimension}!"
    )]
    RingModulusAndDimensionNotCompatible {
        /// Polynomial modulus of Ring.
        ring_modulus: usize,
        /// Polynomial dimension of Ring.
        ring_dimension: usize,
    },
}

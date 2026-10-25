//! Errors produced by the NTT TFHE backend.

use primus_integer::FheUint;

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_glwe::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to construct an NTT table or bind it to TFHE parameters.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// Preparing the selected operation or pairing independent operation state failed.
    #[error(transparent)]
    Parameters(#[from] TfheParameterError),

    /// The selected transform table could not be constructed.
    #[error("failed to construct transform table")]
    TransformTable(#[from] primus_ntt::NttError<T>),
    /// The NTT table was built for a different polynomial length.
    #[error("NTT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the NTT table.
        actual: usize,
    },

    /// The NTT table was built for a different coefficient modulus.
    #[error("NTT modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Coefficient modulus required by the GLWE parameters.
        expected: T,
        /// Coefficient modulus supported by the NTT table.
        actual: T,
    },
}

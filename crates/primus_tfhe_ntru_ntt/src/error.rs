use primus_integer::FheUint;

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to prepare NTRU operations or bind their NTT table.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// Preparing the selected operation or pairing independent operation state failed.
    #[error(transparent)]
    Parameters(#[from] TfheParameterError),

    /// The selected transform table could not be constructed.
    #[error("failed to construct transform table")]
    TransformTable(#[from] primus_ntt::NttError<T>),
    /// The NTT table uses another polynomial length.
    #[error("NTT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// NTT table polynomial length.
        actual: usize,
    },
    /// The NTT table uses another coefficient modulus.
    #[error("NTT modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Required NTRU modulus.
        expected: T,
        /// NTT table modulus.
        actual: T,
    },
}

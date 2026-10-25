pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to prepare NTRU operation state or bind it to a Fourier table.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// Split BR currently has a complete consumer validation only for classic binary.
    #[error(
        "split blind rotation currently requires classic binary; ordinary BR supports trace/SS split independently"
    )]
    UnsupportedSplitBlindRotation,
    /// Unsupported strategy or precision pairing; FusedLastStage and PairedTrace require split trace and SS.
    #[error(
        "Fourier NTRU projection {0:?} is unsupported for this precision (FusedLastStage and PairedTrace require split trace and SS)"
    )]
    UnsupportedProjectionMethod(crate::NtruProjectionMethod),

    /// Preparing the selected operation or pairing independent operation state failed.
    #[error(transparent)]
    Parameters(#[from] TfheParameterError),

    /// The Fourier table uses another polynomial length.
    #[error("Fourier polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// Fourier table polynomial length.
        actual: usize,
    },
}

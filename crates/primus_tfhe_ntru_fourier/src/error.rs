pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    BlockBootstrappingKeyError, BooleanError, CircuitBootstrapParameterError, KeyGenerationError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to prepare NTRU operation state or bind it to a Fourier table.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// The block mode requires a supported coefficient word size.
    #[error(transparent)]
    Block(#[from] BlockBootstrappingKeyError),

    /// Split BR supports classic binary and direct block binary controls.
    #[error(
        "split blind rotation requires classic binary or block binary; ordinary BR supports trace/SS split independently"
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

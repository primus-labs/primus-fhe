//! Errors produced by the Fourier TFHE backend.

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_glwe::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to prepare operation state or bind it to a Fourier table.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// Split35 was selected but its implementation is not enabled in this backend.
    #[error("split35 trace requires the split-trace Cargo feature")]
    SplitTraceUnavailable,

    /// Preparing the selected operation or pairing independent operation state failed.
    #[error(transparent)]
    Parameters(#[from] TfheParameterError),

    /// The Fourier table was built for a different polynomial length.
    #[error("FFT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the Fourier table.
        actual: usize,
    },
}

/// Maps backend-specific preparation failures to the shared secret boundary.
pub(crate) fn glwe_encryption_error(error: primus_glwe::FourierGlweEncryptorError) -> TfheKeyError {
    match error {
        primus_glwe::FourierGlweEncryptorError::SecretDistributionMismatch => {
            TfheKeyError::GlweSecretKeyDistributionMismatch
        }
        primus_glwe::FourierGlweEncryptorError::SecretMagnitudeTooLarge => {
            TfheKeyError::InvalidGlweSecretKeyCoefficient
        }
    }
}

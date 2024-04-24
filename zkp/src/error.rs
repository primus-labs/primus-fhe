//! This module defines some errors that may occur during the protocol execution.
use thiserror::Error;

#[derive(Debug, Error)]
/// error occurred during the protocol
pub enum Error {
    #[error("Verifier reject the proof ({0:?})")]
    /// protocol rejects this proof
    Reject(Option<String>),
    #[error("RNG Error")]
    /// RGN Error
    RNGError,
}

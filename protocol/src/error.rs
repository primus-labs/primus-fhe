//! This module defines some errors that may occur during the protocol execution.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// protocol rejects this proof
    #[error("Verifier reject the proof ({0:?})")]
    Reject(Option<String>),
    #[error("RNG Error")]
    RNGError,
}

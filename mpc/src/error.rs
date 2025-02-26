//! Error types for MPC backend operations.

#[derive(Debug)]
/// Error types for MPC backend operations.
pub enum MPCErr {
    /// Invalid operation.
    InvalidOperation(String),
    /// Input not provided.
    InputNotProvided(u32),
    /// Protocol error.
    ProtocolError(String),
}

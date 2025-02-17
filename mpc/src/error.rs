//! Error types for MPC backend operations.

#[derive(Debug)]
/// Error types for MPC backend operations.
pub enum MPCErr {
    /// MPC ID not found.
    IdNotFound(usize),
    /// Invalid operation.
    InvalidOperation(String),
}

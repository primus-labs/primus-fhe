use std::fmt::Debug;

use thiserror::Error;

/// Errors returned by RNS base construction.
#[derive(Error, Debug)]
pub enum RNSError {
    /// The input basis does not contain any modulus.
    #[error("rns base must contain at least one modulus")]
    EmptyBase,
    /// The modulus at this index cannot be represented as a scalar value.
    #[error("modulus at index {index} cannot be represented as a scalar value")]
    UnrepresentableModulus {
        /// Index of the modulus in the input basis.
        index: usize,
    },
    /// The input basis contains at least one pair of moduli with gcd greater than one.
    #[error("moduli must be pairwise coprime")]
    CoPrimeError,
}

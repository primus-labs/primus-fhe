use std::fmt::Debug;

use thiserror::Error;

/// Errors returned by RNS base construction.
#[derive(Error, Debug)]
pub enum RNSError {
    /// The input basis contains at least one pair of moduli with gcd greater than one.
    #[error("moduli must be pairwise coprime")]
    CoPrimeError,
}

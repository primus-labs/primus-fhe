use std::fmt::Debug;

use thiserror::Error;

/// Invalid RNS bases, extensions or hybrid decomposition partitions.
#[derive(Error, Debug)]
pub enum RnsError {
    /// The input basis does not contain any modulus.
    #[error("rns base must contain at least one modulus")]
    EmptyBase,
    /// A hybrid decomposition must request at least one digit.
    #[error("hybrid RNS decomposition count must be at least one")]
    InvalidDecompositionCount,
    /// A fixed partition size cannot produce the requested number of digits.
    #[error(
        "hybrid RNS decomposition count {decomposition_count} is incompatible with fixed partitioning of {q_moduli_count} Q moduli"
    )]
    IncompatibleDecompositionCount {
        /// Number of moduli in the full `Q` basis.
        q_moduli_count: usize,
        /// Requested number of hybrid-RNS decomposition digits.
        decomposition_count: usize,
    },
    /// An active `Q` basis cannot exceed the full basis used to define its partitioning.
    #[error("active Q basis has {actual} moduli, exceeding the partitioning limit of {maximum}")]
    ActiveBaseTooLarge {
        /// Number of moduli in the requested active basis.
        actual: usize,
        /// Maximum count allowed by the partitioning rule.
        maximum: usize,
    },
    /// The input basis contains at least one pair of moduli with gcd greater than one.
    #[error("moduli must be pairwise coprime")]
    NonCoprimeModuli,
}

use primus_decompose::ApproxSignedBasisError;
use primus_lattice::{GlweSizeError, hybrid::NativeHybridError, radix::NativeRadixError};

use crate::BfvContext;

/// Invalid BFV evaluation-key parameters or numerical binding.
#[derive(Debug, thiserror::Error)]
pub enum BfvEvaluationKeyError {
    /// A key or source owner was created by another local context.
    #[error("BFV evaluation key context provenance mismatch")]
    ContextMismatch,
    /// A requested context level was not prepared.
    #[error("BFV key level {requested} is outside the {available} prepared levels")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        available: usize,
    },
    /// A temporary working basis must be a prefix of the external basis.
    #[error(
        "BFV working level {working} must remove at least as many tail primes as external level {external}"
    )]
    WorkingLevel {
        /// Public input/output level in the context.
        external: usize,
        /// Requested internal level, counting removed tail primes.
        working: usize,
    },
    /// The full ciphertext polynomial length differs.
    #[error("BFV polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLength {
        /// Expected polynomial length.
        expected: usize,
        /// Supplied polynomial length.
        actual: usize,
    },
    /// The plaintext modulus differs.
    #[error("BFV plaintext modulus mismatch: expected {expected}, got {actual}")]
    PlainModulus {
        /// Expected t.
        expected: u64,
        /// Supplied t.
        actual: u64,
    },
    /// A batching encoder's plaintext capacity exceeds the ciphertext ring.
    #[cfg(feature = "batching")]
    #[error("BFV slot capacity {actual} exceeds full polynomial length {maximum}")]
    SlotCapacity {
        /// Largest supported plaintext capacity.
        maximum: usize,
        /// Supplied plaintext capacity.
        actual: usize,
    },
    /// Ordered Q bases have different lengths.
    #[error("BFV modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCount {
        /// Expected retained modulus count.
        expected: usize,
        /// Supplied retained modulus count.
        actual: usize,
    },
    /// An ordered ciphertext modulus differs.
    #[error("BFV modulus mismatch at {index}: expected {expected}, got {actual}")]
    Modulus {
        /// Ordered modulus index.
        index: usize,
        /// Expected modulus.
        expected: u64,
        /// Supplied modulus.
        actual: u64,
    },
    /// Signed digit lifting needs B strictly below every retained prime.
    #[error("BFV gadget radix {radix} is not below ciphertext modulus {modulus}")]
    Radix {
        /// Gadget radix.
        radix: u64,
        /// Rejected retained modulus.
        modulus: u64,
    },
    /// An automorphism exponent must be odd and below 2N.
    #[error("BFV automorphism exponent {exponent} must be odd and below {twice_n}")]
    Exponent {
        /// Supplied exponent.
        exponent: usize,
        /// Exclusive upper bound.
        twice_n: usize,
    },
    /// The radix or retained digit count is incompatible with Q.
    #[error(transparent)]
    Decomposition(#[from] ApproxSignedBasisError),
    /// Invalid native Hybrid numerical parameters.
    #[error(transparent)]
    Hybrid(#[from] NativeHybridError),
    /// Key noise cannot be represented in one auxiliary modulus.
    #[error("BFV Hybrid noise support {bound} must be below key modulus {modulus}")]
    NoiseSupport {
        /// Maximum noise magnitude.
        bound: u64,
        /// Rejected key modulus.
        modulus: u64,
    },
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

impl From<NativeRadixError> for BfvEvaluationKeyError {
    fn from(error: NativeRadixError) -> Self {
        match error {
            NativeRadixError::Decomposition(error) => Self::Decomposition(error),
            NativeRadixError::Layout(error) => Self::Layout(error),
            NativeRadixError::Radix { radix, modulus } => Self::Radix { radix, modulus },
        }
    }
}

pub(super) fn validate_level(
    context: &BfvContext,
    level: usize,
) -> Result<(), BfvEvaluationKeyError> {
    if level >= context.level_count() {
        Err(BfvEvaluationKeyError::Level {
            requested: level,
            available: context.level_count(),
        })
    } else {
        Ok(())
    }
}

pub(super) fn validate_ring_length(
    expected: usize,
    actual: usize,
) -> Result<(), BfvEvaluationKeyError> {
    if expected != actual {
        return Err(BfvEvaluationKeyError::PolynomialLength { expected, actual });
    }
    Ok(())
}

pub(super) fn validate_ordered_moduli(
    expected: &[u64],
    actual: &[u64],
) -> Result<(), BfvEvaluationKeyError> {
    if expected.len() != actual.len() {
        return Err(BfvEvaluationKeyError::ModuliCount {
            expected: expected.len(),
            actual: actual.len(),
        });
    }
    for (index, (&expected, &actual)) in expected.iter().zip(actual).enumerate() {
        if expected != actual {
            return Err(BfvEvaluationKeyError::Modulus {
                index,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

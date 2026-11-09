//! Numerical and binding errors for native role keys.
use primus_decompose::ApproxSignedBasisError;
use primus_lattice::{GlweSizeError, hybrid::NativeHybridError, radix::NativeRadixError};

use crate::BgvContext;

/// Invalid BGV evaluation-key parameters or numerical binding.
#[derive(Debug, thiserror::Error)]
pub enum BgvEvaluationKeyError {
    /// A native key or source client belongs to a different context owner.
    #[error("BGV evaluation key or source client belongs to another context")]
    ContextMismatch,
    /// A requested context level was not prepared.
    #[error("BGV key level {requested} is outside the {available} prepared levels")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        available: usize,
    },
    /// The full ciphertext polynomial length differs.
    #[error("BGV polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLength {
        /// Expected polynomial length.
        expected: usize,
        /// Supplied polynomial length.
        actual: usize,
    },
    /// The noise multiplier/plaintext modulus differs.
    #[error("BGV plaintext modulus mismatch: expected {expected}, got {actual}")]
    PlainModulus {
        /// Expected p.
        expected: u64,
        /// Supplied p.
        actual: u64,
    },
    /// A batching encoder's plaintext ring exceeds the full ciphertext ring.
    #[cfg(feature = "batching")]
    #[error("BGV slot capacity {actual} exceeds ciphertext ring length {maximum}")]
    SlotCapacity {
        /// Full ciphertext-ring length.
        maximum: usize,
        /// Encoder slot capacity.
        actual: usize,
    },
    /// Ordered Q bases have different lengths.
    #[error("BGV modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCount {
        /// Expected retained modulus count.
        expected: usize,
        /// Supplied retained modulus count.
        actual: usize,
    },
    /// An ordered ciphertext modulus differs.
    #[error("BGV modulus mismatch at {index}: expected {expected}, got {actual}")]
    Modulus {
        /// Ordered modulus index.
        index: usize,
        /// Expected modulus.
        expected: u64,
        /// Supplied modulus.
        actual: u64,
    },
    /// Signed digit lifting needs B strictly below every retained prime.
    #[error("BGV gadget radix {radix} is not below ciphertext modulus {modulus}")]
    Radix {
        /// Gadget radix.
        radix: u64,
        /// Rejected retained modulus.
        modulus: u64,
    },
    /// An automorphism exponent must be odd and below 2N.
    #[error("BGV automorphism exponent {exponent} must be odd and below {twice_n}")]
    Exponent {
        /// Supplied exponent.
        exponent: usize,
        /// Exclusive upper bound.
        twice_n: usize,
    },
    /// The radix or retained digit count is incompatible with Q.
    #[error(transparent)]
    Decomposition(#[from] ApproxSignedBasisError),
    /// Native Hybrid basis, transform or geometry is unsupported.
    #[error(transparent)]
    Hybrid(#[from] NativeHybridError),
    /// A key modulus cannot carry the configured coherent integer error sample.
    #[error("BGV Hybrid noise magnitude {bound} is not below key modulus {modulus}")]
    NoiseSupport {
        /// Configured error support.
        bound: u64,
        /// Incompatible QP modulus.
        modulus: u64,
    },
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

impl From<NativeRadixError> for BgvEvaluationKeyError {
    fn from(error: NativeRadixError) -> Self {
        match error {
            NativeRadixError::Decomposition(error) => Self::Decomposition(error),
            NativeRadixError::Layout(error) => Self::Layout(error),
            NativeRadixError::Radix { radix, modulus } => Self::Radix { radix, modulus },
        }
    }
}

pub(super) fn validate_level(
    context: &BgvContext,
    level: usize,
) -> Result<(), BgvEvaluationKeyError> {
    if level >= context.level_count() {
        Err(BgvEvaluationKeyError::Level {
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
) -> Result<(), BgvEvaluationKeyError> {
    if expected != actual {
        return Err(BgvEvaluationKeyError::PolynomialLength { expected, actual });
    }
    Ok(())
}

pub(super) fn validate_plaintext_modulus(
    expected: u64,
    actual: u64,
) -> Result<(), BgvEvaluationKeyError> {
    if expected != actual {
        return Err(BgvEvaluationKeyError::PlainModulus { expected, actual });
    }
    Ok(())
}

pub(super) fn validate_ordered_moduli(
    expected: &[u64],
    actual: &[u64],
) -> Result<(), BgvEvaluationKeyError> {
    if expected.len() != actual.len() {
        return Err(BgvEvaluationKeyError::ModuliCount {
            expected: expected.len(),
            actual: actual.len(),
        });
    }
    for (index, (&expected, &actual)) in expected.iter().zip(actual).enumerate() {
        if expected != actual {
            return Err(BgvEvaluationKeyError::Modulus {
                index,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

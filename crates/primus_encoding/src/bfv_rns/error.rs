use primus_integer::FheUint;

use crate::PlaintextEmbedding;

/// Invalid BFV RNS moduli or conservative recovery bounds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BfvRnsCodecError<T: FheUint> {
    /// The plaintext domain needs at least two residues.
    #[error("plaintext modulus must be at least two, got {modulus:?}")]
    InvalidPlaintextModulus {
        /// Rejected plaintext modulus.
        modulus: T,
    },
    /// Four times the RNS modulus count cannot be represented in `T`.
    #[error("RNS modulus count {count} is too large for BFV decoding")]
    RnsModulusCountTooLarge {
        /// Number of ciphertext moduli.
        count: usize,
    },
    /// The auxiliary modulus must exceed both `t` and four times the modulus count.
    #[error("auxiliary modulus {gamma:?} must exceed {lower_bound:?}")]
    AuxiliaryModulusTooSmall {
        /// Supplied auxiliary modulus.
        gamma: T,
        /// Strict lower bound from the plaintext modulus and RNS count.
        lower_bound: T,
    },
    /// Ciphertext and auxiliary moduli must fit the Shoup arithmetic range.
    #[error("modulus {modulus:?} exceeds Shoup maximum {maximum:?}")]
    ModulusTooLarge {
        /// Rejected modulus.
        modulus: T,
        /// Largest supported modulus.
        maximum: T,
    },
    /// Centered coefficient lifting requires every ciphertext modulus to exceed `t`.
    #[error(
        "RNS modulus {modulus:?} at index {index} must exceed plaintext modulus {plain_modulus:?}"
    )]
    CiphertextModulusTooSmall {
        /// Rejected ciphertext modulus.
        modulus: T,
        /// Plaintext modulus.
        plain_modulus: T,
        /// Position in the ordered ciphertext basis.
        index: usize,
    },
    /// A required inverse does not exist because two moduli are not coprime.
    #[error("moduli {lhs:?} and {rhs:?} must be coprime")]
    NonCoprimeModuli {
        /// First modulus.
        lhs: T,
        /// Second modulus.
        rhs: T,
    },
    /// `Q > 4*(Q % t)*(t-1)` is required for the conservative scaling bound.
    #[error("BFV modulus product is too small for the plaintext scaling error")]
    InsufficientScaleRecovery,
    /// The phase-noise bound leaves insufficient room for scaling and RNS errors.
    #[error(
        "BFV RNS recovery bound fails for noise magnitude {maximum_noise_magnitude:?} with {embedding:?} embedding"
    )]
    InsufficientNoiseRecovery {
        /// Inclusive upper bound on the absolute coefficient of the phase noise.
        maximum_noise_magnitude: T,
        /// Plaintext lifting convention used to bound encoding drift.
        embedding: PlaintextEmbedding,
    },
}

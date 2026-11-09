//! Leveled BGV evaluation with native phase `c0+c1*s = f*m+p*e (mod Q)`.
//!
//! Ciphertext primes must be coprime to the plaintext modulus `p`. Each ciphertext
//! carries a unit correction factor `f`; adjacent prime drops update it, and
//! addition aligns different factors. Fresh ciphertexts start at `f = 1`.
//! This crate uses the full rank-one ciphertext ring for the secret, independently
//! of a plaintext batching subring. Recovery reconstructs the exact centered CRT
//! phase, reduces modulo p and removes `f`; it never invokes a BFV decoder.
//!
//! Shared [`BgvContext`] resources are borrowed by clients and prepared public
//! encryptors. [`BgvMultiplication`](evaluation::BgvMultiplication) combines
//! multiplication and relinearization using prepared scratch. [`advanced`]
//! provides explicit quadratic products. Role executors in [`evaluation`]
//! apply p-preserving gadget products, and
//! [`BgvModulusSwitch`](evaluation::BgvModulusSwitch) drops an adjacent prime
//! using the exact p-constrained quotient.
//! Modulus levels and retained gadget digits are different quantities; each
//! evaluation key belongs to one prepared level and its actual decomposition.
//! [`BgvContext::hybrid_key_parameters`] prepares a shared QP owner for native
//! Hybrid role keys. Pass that handle to key generation in place of a radix
//! configuration; existing requests keep their shape and p-preserving phase.
//! Key-modulus security and complete evaluated noise require separate budgets.
//! Parameter construction checks a fresh private recovery margin, not security
//! or public/evaluated noise. Context-created ciphertexts retain local context
//! and level provenance, while explicit raw storage remains available for
//! advanced composition. Neither provenance nor matching geometry proves an
//! actual secret relationship; raw NTT conventions remain caller contracts.

#![deny(missing_docs)]

mod binding;
mod ciphertext;
mod client;
mod context;
mod correction;
mod evaluation_key;
mod evaluator;
mod modulus_switch;
mod multiplication;
mod parameters;
mod persistence;
pub mod planning;
mod public_key;
mod quadratic;
mod workspace;

pub use ciphertext::{BgvCiphertext, BgvCiphertextBindingError};
pub use client::BgvClient;
pub use context::{BgvContext, BgvContextError};
pub use parameters::{BgvParameters, BgvParametersError};
pub use primus_distr::ErrorDistribution;
pub use primus_encoding::PlaintextEmbedding;
pub use primus_glwe_rns::SecretKeyDistr;

/// Individual public and evaluation keys, with Radix/Hybrid configuration.
pub mod keys {
    pub use crate::evaluation_key::{
        BgvAutomorphismKey, BgvEvaluationKeyConfig, BgvEvaluationKeyError, BgvKeySwitchingKey,
        BgvRelinearizationKey,
    };
    pub use crate::public_key::{BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError};
}

/// Prepared linear, plaintext, ciphertext and key application operations.
pub mod evaluation {
    pub use crate::evaluation_key::{BgvAutomorphism, BgvKeySwitcher, BgvRelinearizer};
    pub use crate::evaluator::BgvEvaluator;
    pub use crate::modulus_switch::BgvModulusSwitch;
    pub use crate::multiplication::BgvMultiplication;
}

/// Explicit quadratic tensors and common-mask input composition.
pub mod advanced {
    pub use crate::evaluation_key::BgvSeededInput;
    pub use crate::multiplication::{square_to, tensor_to};
    pub use crate::quadratic::BgvQuadraticCiphertext;
}

/// Collective key contributions, aggregation and pending relinearization state.
pub mod collective {
    pub use crate::evaluation_key::{
        BgvCollectiveAggregate, BgvCollectiveAutomorphismKey, BgvCollectiveContribution,
        BgvCollectiveError, BgvCollectivePublicKey, BgvCollectiveRelinearization,
        BgvCollectiveRelinearizationState, BgvCollectiveRoundOne, BgvCollectiveSwitchingKey,
        raw_unflooded_partial_phase_to,
    };
}

pub use primus_glwe_rns::persistence::{PublicObjectError, PublicObjectLimits};

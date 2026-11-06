//! Leveled BGV evaluation with native phase `c0+c1*s = m+p*e`.
//!
//! The initial parameter family requires every ciphertext prime `q_i = 1 mod p`.
//! This crate uses the full rank-one ciphertext ring for the secret, independently
//! of a plaintext batching subring. Recovery reconstructs the exact centered CRT
//! phase and reduces modulo p; it never invokes a BFV decoder.
//!
//! Shared [`BgvContext`] resources are borrowed by clients and prepared public
//! encryptors. [`BgvMultiplication`] combines multiplication and relinearization
//! using prepared scratch. Advanced [`BgvEvaluator`] writes explicit quadratic
//! products; role-specific
//! [`BgvRelinearizer`], [`BgvKeySwitcher`] and [`BgvAutomorphism`] apply
//! p-preserving gadget products. [`BgvModulusSwitch`] drops an adjacent prime
//! using the exact p-constrained quotient. All prepared operations reuse scratch.
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
mod evaluation_key;
mod evaluator;
mod modulus_switch;
mod multiplication;
mod parameters;
mod public_key;
mod quadratic;
mod workspace;

pub use ciphertext::{BgvCiphertext, BgvCiphertextBindingError};
pub use client::BgvClient;
pub use context::{BgvContext, BgvContextError};
pub use evaluation_key::{
    BgvAutomorphism, BgvAutomorphismKey, BgvEvaluationKeyConfig, BgvEvaluationKeyError,
    BgvKeySwitcher, BgvKeySwitchingKey, BgvRelinearizationKey, BgvRelinearizer,
};
pub use evaluation_key::{
    BgvCollectiveAggregate, BgvCollectiveAutomorphismKey, BgvCollectiveContribution,
    BgvCollectiveError, BgvCollectivePublicKey, BgvCollectiveRelinearization,
    BgvCollectiveRelinearizationState, BgvCollectiveRoundOne, BgvCollectiveSwitchingKey,
    BgvSeededInput,
};
pub use evaluator::BgvEvaluator;
pub use modulus_switch::BgvModulusSwitch;
pub use multiplication::BgvMultiplication;
pub use parameters::{BgvParameters, BgvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::{BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError};
pub use quadratic::BgvQuadraticCiphertext;

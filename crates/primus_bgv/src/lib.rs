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
//! Parameter construction checks a fresh private recovery margin, not security
//! or public/evaluated noise. Ciphertexts carry storage rather than runtime key
//! identity; the actual secret and NTT convention remain caller contracts.

#![deny(missing_docs)]

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

pub use ciphertext::BgvCiphertext;
pub use client::BgvClient;
pub use context::{BgvContext, BgvContextError};
pub use evaluation_key::{
    BgvAutomorphism, BgvAutomorphismKey, BgvEvaluationKeyError, BgvKeySwitcher, BgvKeySwitchingKey,
    BgvRelinearizationKey, BgvRelinearizer,
};
pub use evaluator::BgvEvaluator;
pub use modulus_switch::BgvModulusSwitch;
pub use multiplication::BgvMultiplication;
pub use parameters::{BgvParameters, BgvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::{BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError};
pub use quadratic::BgvQuadraticCiphertext;

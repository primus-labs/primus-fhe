//! BGV coefficient encryption in native `[c0,c1]` order with phase `m+p*e`.
//!
//! The initial parameter family requires every ciphertext prime `q_i = 1 mod p`.
//! This crate uses the full rank-one ciphertext ring for the secret, independently
//! of a plaintext batching subring. Recovery reconstructs the exact centered CRT
//! phase and reduces modulo p; it never invokes a BFV decoder.
//!
//! Shared [`BgvContext`] resources are borrowed by clients and prepared public
//! encryptors. Prepared coefficient encryption and recovery allocate nothing.
//! Parameter construction checks a fresh private recovery margin, not security
//! or public/evaluated noise. Ciphertexts carry storage rather than runtime key
//! identity; the actual secret and NTT convention remain caller contracts.

#![deny(missing_docs)]

mod ciphertext;
mod client;
mod context;
mod evaluator;
mod parameters;
mod public_key;
mod workspace;

pub use ciphertext::BgvCiphertext;
pub use client::BgvClient;
pub use context::BgvContext;
pub use evaluator::BgvEvaluator;
pub use parameters::{BgvParameters, BgvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::{BgvPublicKey, BgvPublicKeyEncryptor, BgvPublicKeyError};

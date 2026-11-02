//! BFV coefficient encryption and recovery over rank-one `u64` RNS GLWE.
//!
//! [`BfvParameters`] combines the shared codec-free sampling state with the
//! unique [`primus_encoding::BfvRnsCodec`]. Prepared secret/public bindings use
//! [`primus_ntt::U64DcrtTable`] and [`primus_modulus::BarrettModulus<u64>`].
//! Ciphertext storage, keys and evaluation primitives are borrowed from
//! [`primus_glwe_rns`]; message scaling and plaintext recovery belong here.
//!
//! This crate currently provides coefficient encryption/decryption and gadget
//! parameter construction, not a complete leveled BFV evaluator. Construction
//! checks a sufficient fresh private-key recovery bound, not a security level
//! or the complete noise of public encryption and homomorphic evaluation.

#![deny(missing_docs)]

mod parameters;
mod public_key;
mod secret_key;
mod workspace;

pub use parameters::{BfvParameters, BfvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::BfvPublicKeyEncryptor;
pub use secret_key::BfvSecretKeyContext;
pub use workspace::BfvDecryptWorkspace;

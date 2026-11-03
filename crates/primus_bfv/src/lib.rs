//! BFV coefficient encryption and recovery over rank-one `u64` RNS GLWE.
//!
//! [`BfvParameters`] combines the shared codec-free sampling state with the
//! unique [`primus_encoding::BfvRnsCodec`]. Prepared secret/public bindings use
//! [`primus_ntt::U64DcrtTable`] and [`primus_modulus::BarrettModulus<u64>`].
//! [`BfvCiphertext`] and [`BfvPublicKey`] natively use `[c0,c1]` and phase
//! `c0+c1*s`. Secret storage and numerical primitives are reused from
//! [`primus_glwe_rns`], without changing the actual coefficient secret.
//! Raw GLWE retains mask/body order and phase `b-a*s`; representation bridges
//! are explicit and are not used by ordinary BFV encryption or recovery.
//!
//! This crate currently provides coefficient encryption/decryption and gadget
//! parameter construction, not a complete leveled BFV evaluator. Construction
//! checks a sufficient fresh private-key recovery bound, not a security level
//! or the complete noise of public encryption and homomorphic evaluation.

#![deny(missing_docs)]

mod ciphertext;
mod parameters;
mod public_key;
mod secret_key;
mod workspace;

pub use ciphertext::BfvCiphertext;
pub use parameters::{BfvParameters, BfvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::{BfvPublicKey, BfvPublicKeyEncryptor};
pub use secret_key::BfvSecretKeyContext;
pub use workspace::BfvDecryptWorkspace;

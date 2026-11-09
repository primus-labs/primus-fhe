//! CRT/DCRT GLWE operations and Hybrid-RNS key switching.
//!
//! [`CrtGlweEncryptionParameters`] prepares layout and sampling without plaintext
//! encoding. Raw encryption binds sampling, basis and transform resources directly.
//! [`CrtGlevParameters`] owns an ordered RNS base and gadget decomposition,
//! independently of encryption sampling. Message encoding and recovery belong to scheme crates.

#![deny(missing_docs)]

mod automorphism;
mod crt;
mod dcrt;
mod expansion;
mod key_switch;
mod parameter;
mod public_key;
mod secret_key;
mod workspace_pool;

/// Coefficient-domain GLWE ciphertext over an ordered RNS basis.
pub type CrtGlweCiphertext<T> = primus_lattice::glwe::CrtGlwe<T>;

/// NTT-domain GLWE ciphertext over an ordered RNS basis.
pub type DcrtGlweCiphertext<T> = primus_lattice::glwe::DcrtGlwe<T>;

pub use crt::{
    CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffParallelEvaluator, CrtGlweTraceEvaluator, CrtGlweTraceKey,
};
pub use dcrt::{
    DcrtGlweAutoEvaluator, DcrtGlweAutoKey, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffParallelEvaluator, DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey,
    DcrtGlweTraceEvaluator, DcrtGlweTraceKey,
};
pub use key_switch::{
    DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey,
};
pub use parameter::{
    CrtGlevParameters, CrtGlevParametersError, CrtGlweEncryptionParameters,
    CrtGlweEncryptionParametersError, RnsDomainError,
};
pub use primus_glwe::{GlweSecretKey, SecretKeyDistr};
pub use primus_lattice::{RnsGadgetSize, RnsGlweSize};
pub use public_key::{
    DcrtGgswEncryptor, DcrtGlwePublicKey, DcrtGlwePublicKeyWorkspace, DcrtGlweRawPublicKeyEncryptor,
};
pub use secret_key::{DcrtGlevEncryptor, DcrtGlweRawSecretKeyContext, DcrtGlweSecretKey};

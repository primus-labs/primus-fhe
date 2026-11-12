//! NTT backend for GLWE-based TFHE.
//!
//! # Start here
//!
//! 1. Select [`experimental::CLASSIC_PBS_U64`], a numerical [`PbsConfig`].
//!    [`PbsParameters::try_from_config`] prepares its domain once; prepared
//!    parameters can also be moved into a context directly.
//! 2. Create a complete [`TfheContext`] with [`TfheContext::try_from_pbs_config`].
//!    [`TfheContext::try_generate_keys`] generates the retained BR and KS choices; [`TfheContext::evaluator`] takes only the generated server key.
//! 3. Create [`TfheContext::encryptor`] and [`TfheContext::pbs_decryptor`]
//!    using only the external secret. They derive Rounded encodings from
//!    the config's input/output messages; no LUT or explicit codec is needed.
//! 4. Use [`TfheContext::pbs_lookup_table_compiler`] and
//!    [`LookupTableCompiler::compile_fn`], then reuse
//!    [`Evaluator::apply_lookup_table_to`] with caller-owned LWE output storage.
//!    ManyLUT shares those clients; factorized MVB uses
//!    [`TfheContext::compile_mvb_fn`] and [`TfheContext::mvb_decryptor`] for
//!    Scaled output. Named message overrides reuse the same keys and do not
//!    change existing clients. Advanced explicit-codec factories remain on
//!    [`PbsParameters`].
//!
//! # Other operations
//!
//! [`experimental`] pairs PBS, ManyLUT, MVB and CBS with their teaching
//! message domains. Each example prepares its matching config once.
//!
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CbsEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`block`]: contiguous block-binary controls with independently encrypted
//!   empty-block dummies, single-input and bounded batch workspaces; choose
//!   [`BlindRotationMethod::Block`] with a matching secret distribution.
//!
//! [`Evaluator`] owns common [`bootstrap::BootstrapResources`] and the ordinary return stage.
//! Default [`CbsEvaluator`] owns its input/BR resources; low-level
//! [`circuit_bootstrap::CircuitBootstrapEvaluator`] borrows common resources per call.
//! [`FactorizedEvaluator`] owns a complete PBS evaluator and its factor workspace.
//! Standalone resources include input KS for KS→BR, but no output KS for BR→KS.
//! The specialized constructors document their allocation and borrowing contracts.
//!
//! [`TfheContext::try_generate_circuit_bootstrap_keys`] generates a complete CBS
//! bundle, including the BR/KS [`ServerKey`] for downstream LWE returns.
//! [`TfheContext::compile_cbs_fn`] compiles F using retained input/gadgets;
//! [`TfheContext::circuit_bootstrap_evaluator_with_lookup_table`] binds the complete
//! key and moves the program into [`CbsEvaluator`]. Candidate ring clients take
//! independent t_ring via [`TfheContext::accumulator_client`]. CBS output uses its
//! gadget basis; CMux requires bit-valued F across the programmed input domain.
//!
//! # Composition and representation
//!
//! [`PbsParameters`] and [`CbsParameters`] retain complete operation choices.
//! [`TfheContext`] retains those capabilities while sharing one [`PbsParameters`]
//! domain with required KS state and owning one transform table.
//! Keys and mutable evaluation scratch remain independently owned.
//!
//! [`key`] contains evaluation material and component generation. Common workflow types
//! are re-exported at this root; lower-level material is documented in its own module.
//! [`bootstrapping_key`] and [`blind_rotation`] expose raw ring-control operations.
//! [`Evaluator::try_from_parts`] borrows independent BR and ring KS material.
//! CBS component binding omits KS for BR→KS, but requires it for KS→BR input preparation.
//! Both PBS orders support Classic binary/ternary and Block binary keys.
//! Keys and values must use this context's NTT root and ordering convention.
//! Raw ciphertexts do not record secret identity, encoding or noise margins.

#![deny(missing_docs)]

/// Experimental u64 arithmetic fixtures paired with message/operation choices.
///
/// Security and failure probability are unassessed; this module records the
/// source revision and operation contracts. Each constant contains the BR choice.
pub mod experimental;

use primus_modulus::BarrettModulus;

mod accumulator;
pub mod blind_rotation;
pub mod block;
pub mod bootstrap;
pub mod bootstrapping_key;
pub mod circuit_bootstrap;
mod client;
mod context;
mod error;
mod evaluator;
pub mod factorized;
pub mod key;
mod lookup_table;

pub mod boolean;

pub use error::{
    BlockBootstrappingKeyError, CircuitBootstrapParameterError, KeyGenerationError,
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

pub use accumulator::AccumulatorClient;
#[doc(inline)]
pub use circuit_bootstrap::CbsEvaluator;
pub use context::TfheContext;
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};
#[doc(inline)]
pub use key::{CircuitBootstrapServerKey, KeyGenerator, ServerKey};
pub use primus_tfhe::{
    BivariateLookupTable, BlindRotationMethod, CbsGadgetConfig, CbsInputEncoding,
    CircuitBootstrapLookupTable, ClientError, DecompositionConfig, FactorizedLookupTable,
    GadgetEncryptionConfig, InterleavedLookupTable, LookupTable, LookupTableCompiler, Lwe,
    LweCiphertext, LweSecretKeyRef, PbsMessageConfig,
};
pub use primus_tfhe_glwe::{
    ClientKey, EncryptionKey, ExternalLweSecretKey, FourierTracePrecision, PbsOrder,
};

pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Borrows an external LWE secret or public key selected by the context.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::Encryptor<'a, T, BarrettModulus<T>, Key, LM>;

/// Input client bound to the configured padded or MSB Boolean CBS geometry.
pub type CbsEncryptor<'a, T, Key = LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::CbsEncryptor<'a, T, BarrettModulus<T>, Key, LM>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::Decryptor<'a, T, BarrettModulus<T>, LM>;

/// Complete numerical PBS choices for this backend.
pub type PbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::PbsConfig<T, BarrettModulus<T>, LM>;

/// Complete numerical CBS choices for this backend.
pub type CbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::CbsConfig<T, BarrettModulus<T>, LM>;

pub use primus_tfhe_glwe::{LweConfig, ModulusConfig, ModulusConfigError};

/// Complete PBS parameters, including required key switching and default messages.
pub type PbsParameters<T, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::PbsParameters<T, BarrettModulus<T>, LM>;

/// Complete ring-output CBS parameters and selector-input encoding.
pub type CbsParameters<T, LM = BarrettModulus<T>> =
    primus_tfhe_glwe::CbsParameters<T, BarrettModulus<T>, LM>;

/// Prepared ring key-switch parameters at this backend's ciphertext modulus.
pub type GlweKeySwitchingParameters<T> =
    primus_glwe::GlweKeySwitchingParameters<T, BarrettModulus<T>>;

//! NTT backend for NTRU-based TFHE.
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
//! [`experimental`] pairs sparse PBS, ManyLUT, MVB, CBS and one-hot with their
//! teaching message domains. Each example prepares its matching config once.
//!
//! - [`InterleavedLookupTable`]: several functions of one input using ordinary PBS workspace.
//! - [`factorized`]: a prepared MVB program and [`FactorizedEvaluator`], with Scaled outputs.
//! - [`boolean`]: Boolean clients and gates with plaintext modulus four.
//! - [`circuit_bootstrap`]: optional trace/scheme-switch material and
//!   [`CbsEvaluator`], producing accumulator-secret gadget controls for CMUX.
//! - [`sparse`]: fixed-weight binary bucket material; choose [`BlindRotationMethod::Sparse`]
//!   in the operation config, then use [`KeyGenerator::try_generate_server_key`].
//!
//! [`Evaluator`] owns common [`bootstrap::BootstrapResources`] and client-return buffers.
//! Default [`CbsEvaluator`] / [`OneHotEvaluator`] own common BR resources;
//! low-level CBS/one-hot state borrows them per call. [`FactorizedEvaluator`]
//! owns PBS and one extra NTT polynomial, borrowing the same context and keys.
//! Standalone CBS/one-hot can use resources without allocating return buffers.
//! [`primus_ntru::LweReturnEvaluator`] supports independent coefficient-domain returns.
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
//! [`key::BlindRotationKey`], [`primus_ntru::NtruLweKeySwitchingKey`] and
//! [`circuit_bootstrap::CircuitBootstrapKey`] can be independently generated and borrowed through
//! [`Evaluator::try_from_parts`] or [`bootstrap::BootstrapResources::try_new`] plus CBS/one-hot
//! `try_new`. [`ServerKey::into_parts`] moves out the bundle's components.
//! [`CircuitBootstrapServerKey`] combines one [`ServerKey`] with required CBS material.
//! CBS/one-hot evaluation borrows BR/CBS; downstream LWE returns reuse its KS key.
//! Classic binary/ternary and sparse fixed-weight binary BR support PBS, MVB,
//! CBS and one-hot. CBS/one-hot require trace and scheme-switch material.
//! Only accumulator secrets undergo NTRU invertibility screening; external LWE secrets are independent.
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
mod blind_rotation;
pub mod boolean;
pub mod bootstrap;
pub mod circuit_bootstrap;
mod client;
mod context;
mod error;
mod evaluator;
pub mod factorized;
pub mod key;
mod lookup_table;
pub mod sparse;

pub use accumulator::AccumulatorClient;
pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};
pub use context::TfheContext;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError,
    SparseBootstrappingKeyError, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};
#[doc(inline)]
pub use evaluator::Evaluator;
#[doc(inline)]
pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};
#[doc(inline)]
pub use key::{CircuitBootstrapServerKey, KeyGenerator, ServerKey};

pub use primus_tfhe::{
    BivariateLookupTable, BlindRotationMethod, CbsGadgetConfig, CircuitBootstrapLookupTable,
    ClientError, DecompositionConfig, FactorizedLookupTable, GadgetEncryptionConfig,
    InterleavedLookupTable, LookupTable, LookupTableCompiler, Lwe, LweCiphertext, LweSecretKeyRef,
    PbsMessageConfig,
};
pub use primus_tfhe_ntru::{ClientKey, EncryptionKey, LwePublicKey};

#[doc(inline)]
pub use circuit_bootstrap::{
    CbsEvaluator, NlevSelectors, NttNgswSelectors, OneHotBootstrapError, OneHotEvaluator,
};

/// Secret-key or LWE public-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T, Key = LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::Encryptor<'a, T, LM, Key>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T, LM = BarrettModulus<T>> = primus_tfhe_ntru::Decryptor<'a, T, LM>;

/// Complete numerical PBS choices for this backend.
pub type PbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::PbsConfig<T, BarrettModulus<T>, LM>;

/// Complete numerical CBS choices for this backend.
pub type CbsConfig<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::CbsConfig<T, BarrettModulus<T>, LM>;

pub use primus_tfhe_ntru::{LweConfig, ModulusConfig, ModulusConfigError, NtruProjectionMethod};

/// Complete PBS parameters, including required key switching and default messages.
pub type PbsParameters<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::PbsParameters<T, BarrettModulus<T>, LM>;

/// Complete ring-output CBS parameters and selector-input encoding.
pub type CbsParameters<T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::CbsParameters<T, BarrettModulus<T>, LM>;

/// Prepared independent LWE return-key parameters.
pub use primus_tfhe_ntru::LweKeySwitchingParameters;

pub use primus_tfhe_ntru::{FourierCbsPrecision, FourierPrecision};

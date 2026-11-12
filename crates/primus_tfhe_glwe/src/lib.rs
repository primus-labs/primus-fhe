//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.
//!
//! [`ClientKey::generate`] creates coefficient-domain client secrets without
//! transform tables. Backend contexts generate paired client/server keys.
//!
//! # Role in the backend workflow
//!
//! Prepare [`PbsConfig`] with [`PbsParameters::try_from_config`], or pass
//! [`CbsConfig`] to [`CbsParameters::try_from_config`].
//! Common parameters own KS and default messages. CBS adds its input encoding and
//! [`CbsGadgetParameters`], retaining existing KS without preparing unused return state.
//! Both share [`PbsParameters`] for numerical domains and sampling state.
//! It also provides a [`LookupTableCompiler`] for Rounded LUTs. [`ClientKey`] owns the
//! complete setup secrets; [`Encryptor`] and [`Decryptor`] borrow only the external
//! message secret and bind its codec. Choose the NTT/Fourier
//! backend for transform tables, key generation and evaluators. Both backends
//! use [`BlockGlweBootstrappingKey`] for coefficient-domain block controls.
//! Concrete backends provide experimental u64 operation/message configurations.
//! This family supplies the shared numerical configuration types and sampling state.
//! [`KeyGenerationError`] and [`TfheClientError`] report key generation and family
//! client construction; operations return shared [`ClientError`] or [`BooleanError`].
//!
//! [`PbsMessageConfig`] defaults to equal input/output message moduli and allows
//! an independent output override. Backend contexts prepare LUT compilers and
//! clients directly: Rounded outputs use `pbs_decryptor`, Scaled MVB outputs
//! use `mvb_decryptor`.
//! For CBS, [`CbsParameters::compile_lookup_table_fn`] uses its retained input
//! encoding and programs gadget-scaled integers. Backend contexts provide
//! `cbs_encryptor` for that input geometry, including MSB Boolean; candidate
//! ring clients take independent t_ring at Q.
//!
//! # Public-key clients
//!
//! [`PbsParameters::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the external client secret: small LWE for bootstrap-then-key-switch, or the
//! signed GLWE coefficient vector for key-switch-then-bootstrap. Pass the public
//! key to [`PbsParameters::public_encryptor`]; keep the external secret for decryption.
//! NTT/Fourier contexts provide `public_encryptor` and `boolean_public_encryptor`.
//! The `Key` parameter selects secret/public encryption at compile time, sharing
//! message checks and encoding APIs. It does not change the PBS output domain.
//!
//! Public-key identity and combined-noise requirements are documented on
//! [`EncryptionKey`]; generation parameters and storage size are documented
//! on [`PbsParameters::try_generate_public_key`].
//!
//! # Reusing client ciphertext storage
//!
//! [`Encryptor::encrypt_to`], [`Encryptor::encrypt_padded_to`] and
//! [`Encryptor::encrypt_centered_to`] overwrite a mutable [`Lwe`] view without
//! allocating, for either secret or public keys. Use `as_mut_view()` to reuse
//! an owned ciphertext, and `as_view()` to decrypt it. Message and dimension
//! errors leave output and RNG unchanged. Backend `Encryptor` aliases expose
//! these same methods.

#![deny(missing_docs)]

mod block;
mod circuit_bootstrap;
mod client;
mod config;
mod controls;
mod error;
mod key;
mod lookup_table;
mod parameters;

use primus_glwe::{GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweSecretKey};
use primus_lwe::LweSecretKey;

pub use block::BlockGlweBootstrappingKey;
pub use circuit_bootstrap::CbsGadgetParameters;
pub use config::{CbsConfig, FourierTracePrecision, PbsConfig};
pub use controls::GlweBlindRotationControls;
pub use error::{
    BlockBootstrappingKeyError, CircuitBootstrapParameterError, KeyGenerationError,
    TfheClientError, TfheKeyError, TfheParameterError,
};
pub use key::{ClientKey, ExternalLweSecretKey};
pub use parameters::{CbsParameters, PbsEvaluationParameters, PbsOrder, PbsParameters};
pub use primus_tfhe::{LweConfig, ModulusConfig, ModulusConfigError};

pub use primus_tfhe::{
    BOOLEAN_PLAINTEXT_BITS, BivariateLookupTable, BooleanError, BooleanEvaluator, BooleanGate,
    CbsGadgetConfig, CbsInputEncoding, CircuitBootstrapLookupTable, ClientError,
    DecompositionConfig, EncryptionKey, GadgetEncryptionConfig, InterleavedLookupTable,
    LookupTable, LookupTableCompiler, LookupTableError, Lwe, LweCiphertext, LweSecretKeyRef,
    PbsMessageConfig, ProgrammableBootstrap, ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

pub use primus_glwe::{BlockOccupancy, SecretKeyDistr};

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;

pub use client::{
    BooleanDecryptor, BooleanEncryptor, CbsEncryptor, Decryptor, Encryptor, ExternalLweClient,
};

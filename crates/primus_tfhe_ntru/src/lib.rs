//! Backend-independent client API and parameters for NTRU-based TFHE.
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
//! backend for transform tables, key generation and evaluators. Shared sparse
//! coefficient storage is provided by [`SparseNtruBootstrappingKey`].
//! Concrete backends provide experimental u64 operation/message configurations.
//! This family supplies the shared numerical configuration types and sampling state.
//! [`KeyGenerationError`] and [`TfheClientError`] report key generation and family
//! client construction; operations return shared [`ClientError`] or [`BooleanError`].
//!
//! Ordinary clients use [`PbsParameters::encryptor`] and [`PbsParameters::pbs_decryptor`].
//! Their named message-modulus overrides pair with the backend compiler; factorized
//! MVB instead uses [`PbsParameters::mvb_decryptor`] or an explicit Scaled
//! [`PbsParameters::ring_return_decryptor`]. Prepared codec factories remain available
//! for composition, including high-precision LUT clients.
//! For CBS, [`CbsParameters::compile_lookup_table_fn`] uses its retained input
//! encoding and programs gadget-scaled integers. Backend contexts share the
//! ordinary input encryptor; candidate ring clients take independent t_ring at Q.
//!
//! # Public-key clients
//!
//! [`PbsParameters::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the independent binary or ternary external secret. Pass it to
//! [`PbsParameters::public_encryptor`] or a backend context's `public_encryptor`; keep the paired
//! external secret for decryption.
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
//!
//! # Independent NTRU→LWE returns
//!
//! [`LweReturnEvaluator`] binds coefficient-domain return keys and q,
//! independent of NTT/FFT or one-hot resources. It supports scalar, shared-input
//! prefix and different-input stream returns with separately prepared scalar/batch
//! workspaces and no online allocation.

#![deny(missing_docs)]

mod circuit_bootstrap;
mod client;
mod config;
mod error;
mod key;
mod lookup_table;
mod one_hot;
mod parameters;
mod sparse;

pub use circuit_bootstrap::CbsGadgetParameters;
pub use config::{CbsConfig, PbsConfig};
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};
pub use key::ClientKey;
pub use one_hot::{NlevSelectors, OneHotBootstrapError, OneHotLookupTable};
pub use parameters::{CbsParameters, PbsParameters};
pub use primus_lwe::LweKeySwitchingParameters;
pub use primus_tfhe::{LweConfig, ModulusConfig, ModulusConfigError};
pub use sparse::SparseNtruBootstrappingKey;

pub use primus_ntru::{
    LweReturnBatchWorkspace, LweReturnEvaluator, NlevParameters, NtruParameters,
    NtruProjectionMethod, NtruSecretKey,
};
pub use primus_tfhe::{
    BOOLEAN_PLAINTEXT_BITS, BivariateLookupTable, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, CbsGadgetConfig, CircuitBootstrapLookupTable, ClientError,
    DecompositionConfig, Decryptor, EncryptionKey, Encryptor, FactorizedPbsCodecs,
    GadgetEncryptionConfig, InterleavedLookupTable, LookupTable, LookupTableCompiler,
    LookupTableError, Lwe, LweCiphertext, LweSecretKeyRef, PbsCodecs, PbsMessageConfig,
    ProgrammableBootstrap, ProgrammableBootstrapInterleaved, RoundedPbsCodecs, TfheEvaluationError,
};

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;

pub use config::FourierCbsPrecision;
pub use primus_ntru::FourierPrecision;

//! Representation-independent building blocks for TFHE execution backends.
//!
//! Choose [`LookupTable`] for one function, [`InterleavedLookupTable`] for several
//! Rounded outputs, [`FactorizedLookupTable`] for Scaled MVB programs, or
//! [`BivariateLookupTable`] to pack bounded inputs. Backends prepare tables/keys and
//! execute these programs; this crate does not own a transform context or server key.
//! [`LookupTableCompiler`] shares the encoding environment for ordinary Rounded LUTs.
//! [`PbsMessageConfig`] defaults to equal input/output message moduli and prepares
//! [`PbsCodecs`] with an explicit output override, including independent q/Q roles.
//! [`CircuitBootstrapLookupTable`] programs integer functions at gadget scales;
//! it is distinct from ordinary Rounded/Scaled output LUTs. Families compile the
//! program, and concrete backends bind it to CBS keys and reusable workspace.
//! [`BooleanEvaluator`] composes the small PBS traits for Boolean gate evaluation.
//!
//! [`Encryptor`], [`Decryptor`] and their Boolean wrappers share external LWE
//! workflows through [`LweClientParameters`], without a transform backend.
//! Client and evaluation APIs take borrowed [`Lwe`] views for single operands;
//! allocating methods return [`LweCiphertext`].
//!
//! Ring-length arguments use the checked [`primus_shape::PolyLength`] shared with GLWE/NTRU.
//! LUT compilation additionally checks rotation-domain and encoding requirements.
//!
//! Raw LWE views carry no encoding or key identity. Encoding and Boolean
//! evaluators bind encoding and reusable workspace around these raw values.

#![deny(missing_docs)]

mod boolean;
mod bootstrap;
mod client;
mod error;
mod lookup_table;
mod message;
mod parameters;

pub mod rotation;

pub use boolean::{BOOLEAN_PLAINTEXT_BITS, BooleanEvaluator, BooleanGate};
pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
pub use client::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientError, Decryptor, EncryptionKey,
    Encryptor, LweClientParameters,
};
pub use error::{LookupTableError, TfheEvaluationError};
pub use lookup_table::{
    BivariateLookupTable, CbsInputEncoding, CircuitBootstrapLookupTable, FactorizedLookupTable,
    InterleavedLookupTable, LookupTable, LookupTableCompiler, front_half_domain_len,
};
pub use message::{FactorizedPbsCodecs, PbsCodecs, PbsMessageConfig, RoundedPbsCodecs};
pub use parameters::{BlindRotationMethod, CbsGadgetConfig, GadgetEncryptionConfig};
pub use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
pub use primus_lattice::lwe::Lwe;
pub use primus_lwe::{LweCiphertext, LweConfig, LweConfigError, LweSecretKeyRef};
pub use primus_modulus::{ModulusConfig, ModulusConfigError};

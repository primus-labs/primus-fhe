//! BFV coefficient encryption and leveled evaluation over rank-one `u64` RNS.
//!
//! Use [`BfvParameters`], [`BfvContext`] and [`BfvClient`] for ordinary setup
//! and encryption. Find key data and backend configuration in [`keys`] and
//! prepared operations with reusable scratch in [`evaluation`].
//! [`planning`] covers ordinary leveled requests, and [`advanced`] exposes
//! explicit tensor and recovery resources. [`collective`] covers shared keys.
//!
//! [`BfvParameters::try_coefficients`] prepares ordinary coefficient parameters
//! with a default decoder modulus. [`BfvContext`] owns the sampling parameters,
//! one [`primus_ntt::U64DcrtTable`] and the requested prefix-level codecs.
//! [`BfvClient`] owns one secret and reusable recovery scratch.
//! [`BfvEvaluator`](`evaluation::BfvEvaluator`) provides linear and plaintext operations.
//! [`BfvModulusSwitch`](`evaluation::BfvModulusSwitch`) drops one final prime using
//! exact coefficientwise nearest rounding. Ciphertexts store `[c0,c1]` with phase
//! `c0+c1*s`.
//!
//! Level zero uses the complete Q basis. [`BfvContext::try_new`] prepares only
//! that level; [`BfvContext::try_with_levels`] includes the requested lower
//! prefixes in its level count. Context-allocated storage and views retain local
//! context/level provenance; normal recovery infers its recorded level. Public
//! and evaluation keys reject preparation under a foreign context owner.
//! Explicit `from_raw` storage retains caller-owned NTT/scale/secret contracts;
//! `try_bind_ciphertext` adopts canonical words without proving those facts.
//! Even bound provenance does not certify actual secrets or evaluated noise.
//!
//! [`PlaintextEmbedding`] selects unsigned or centered integer lifts of N
//! canonical coefficients in `[0,t)`. Plaintext addition applies the level's
//! delta once, whereas plaintext multiplication uses an unscaled lift in the
//! negacyclic coefficient ring. The unique [`primus_encoding::BfvRnsCodec`]
//! recovers the exact message under its complete phase-error bound; it is not
//! an arbitrary-phase exact-rounding oracle. Parameter construction establishes
//! a sufficient fresh private recovery bound, not security or recovery after
//! public encryption, evaluation and switching.
//!
//! Prepared operations reuse owned scratch without allocating.
//! [`BfvSecretKeyContext`](`advanced::BfvSecretKeyContext`) borrows an existing secret.
//! [`BfvPublicKeyEncryptor`](`keys::BfvPublicKeyEncryptor`) borrows a public key.
//! The explicit raw GLWE bridge uses mask/body order and phase `b-a*s`.
//! Optional `batching` uses shared slot encoding and plaintext subring embedding
//! from `primus_encoding`; secrets and ciphertexts retain their full ring.
//! [`BfvMultiplier`](`advanced::BfvMultiplier`) computes exact integer tensors with a
//! computation-only auxiliary basis before `round(t*T/Q)`. Private tests check
//! the result against an independent integer schoolbook oracle. The resulting
//! [`BfvQuadraticCiphertext`](`advanced::BfvQuadraticCiphertext`) is already scaled
//! for [`BfvRelinearizer`](`evaluation::BfvRelinearizer`). Native gadget keys also
//! support key switching and encrypted automorphisms at each prepared level.
//! [`BfvMultiplication`](`evaluation::BfvMultiplication`) prepares multiplication
//! and relinearization together, deriving the level from the key and reusing
//! intermediate storage. Its
//! [`try_with_backend`](`evaluation::BfvMultiplication::try_with_backend`) constructor
//! also supports HPSPOVERQ with a separate arithmetic budget, bounded one-sided
//! P/Q scaling residual and centered wrap correction.
//!
//! [`BfvLeveledMultiplication`](`evaluation::BfvLeveledMultiplication`) rounds both
//! inputs to a smaller working prefix, multiplies and relinearizes there, then
//! scales back into external Q. [`BfvLeveledParameters`](`planning::BfvLeveledParameters`)
//! admits ordinary binary circuits using deterministic error bounds from actual
//! sampler support and shared immutable key resources. Its correctness scope
//! covers ordinary keys generated under the specified sampling laws.

#![deny(missing_docs)]

mod ciphertext;
mod client;
mod context;
mod evaluation_key;
mod evaluator;
mod leveled_parameters;
mod modulus_switch;
mod multiplication;
mod parameters;
mod persistence;
mod public_key;
mod quadratic;
mod secret_key;
mod working_basis;
mod workspace;

pub use ciphertext::{BfvCiphertext, BfvCiphertextBindingError};
pub use client::BfvClient;
pub use context::{BfvContext, BfvContextError};
pub use parameters::{BfvParameters, BfvParametersError};
pub use primus_distr::ErrorDistribution;
pub use primus_encoding::PlaintextEmbedding;
pub use primus_glwe_rns::SecretKeyDistr;

/// Individual public and evaluation keys, with Radix/Hybrid configuration.
pub mod keys {
    pub use crate::evaluation_key::{
        BfvAutomorphismKey, BfvEvaluationKeyConfig, BfvEvaluationKeyError, BfvKeySwitchingKey,
        BfvRelinearizationKey,
    };
    pub use crate::public_key::{BfvPublicKey, BfvPublicKeyEncryptor, BfvPublicKeyError};
}

/// Prepared linear, plaintext, ciphertext and key application operations.
pub mod evaluation {
    pub use crate::evaluation_key::{BfvAutomorphism, BfvKeySwitcher, BfvRelinearizer};
    pub use crate::evaluator::BfvEvaluator;
    pub use crate::modulus_switch::{BfvModulusSwitch, BfvModulusSwitchError};
    pub use crate::multiplication::{
        BfvLeveledMultiplication, BfvMultiplication, BfvMultiplicationBackend, BfvMultiplyError,
    };
}

/// Parameter admission and error bounds for ordinary BFV circuits.
pub mod planning {
    pub use crate::leveled_parameters::{
        BfvLeveledErrorLedger, BfvLeveledFreshErrorLedger, BfvLeveledKeyBackend,
        BfvLeveledParameterError, BfvLeveledParameters, BfvLeveledRequest, BfvLeveledStep,
    };
}

/// Explicit scaled tensors, secret binding and recovery scratch.
pub mod advanced {
    pub use crate::multiplication::BfvMultiplier;
    pub use crate::quadratic::BfvQuadraticCiphertext;
    pub use crate::secret_key::BfvSecretKeyContext;
    pub use crate::workspace::BfvDecryptWorkspace;
}

/// Collective key contributions, aggregation and BFV-specific lookup operations.
pub mod collective {
    pub use crate::evaluation_key::{
        BfvCollectiveAggregate, BfvCollectiveAutomorphismKey, BfvCollectiveContribution,
        BfvCollectiveError, BfvCollectivePublicKey, BfvCollectiveRelinearization,
        BfvCollectiveRelinearizationRound1, BfvCollectiveRelinearizationState,
        BfvCollectiveSwitchingKey, BfvFreshLookup, BfvFreshLookupKey, BfvRawQuadraticAggregate,
    };
}

pub use primus_glwe_rns::persistence::{PublicObjectError, PublicObjectLimits};

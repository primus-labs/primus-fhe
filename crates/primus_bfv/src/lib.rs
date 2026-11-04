//! BFV coefficient encryption and leveled evaluation over rank-one `u64` RNS.
//!
//! [`BfvParameters::try_coefficients`] prepares ordinary coefficient parameters
//! with a default decoder modulus. [`BfvContext`] owns the sampling parameters,
//! one [`primus_ntt::U64DcrtTable`] and the requested prefix-level codecs.
//! [`BfvClient`] owns one secret and reusable recovery scratch; [`BfvEvaluator`]
//! provides linear and plaintext operations. [`BfvModulusSwitch`] drops one
//! final prime using exact coefficientwise nearest rounding, preserving native
//! `[c0,c1]` storage and phase `c0+c1*s` throughout.
//!
//! Level zero uses the complete Q basis. [`BfvContext::try_new`] prepares only
//! that level; [`BfvContext::try_with_levels`] includes the requested lower
//! prefixes in its level count. Storage/view types do not certify level, actual
//! secret identity, canonical residues or NTT evaluation convention. Operations
//! check complete lengths; those numerical identities remain caller contracts.
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
//! Prepared operations reuse owned scratch without allocating. Advanced
//! [`BfvSecretKeyContext`], [`BfvPublicKeyEncryptor`] and explicit raw-GLWE
//! bridges remain available for existing resource owners. Raw GLWE uses
//! mask/body order and `b-a*s`; ordinary BFV operations never pass through it.
//! Optional `batching` uses shared slot encoding and plaintext subring embedding
//! from `primus_encoding`; secrets and ciphertexts retain their full ring.
//! [`BfvMultiplier`] computes exact integer tensors with a computation-only
//! auxiliary basis before `round(t*T/Q)`. An independent reference retains a
//! separate exact integer schoolbook oracle in private tests. The raw integer
//! stage is internal; the scaled [`BfvQuadraticCiphertext`] alone enters
//! [`BfvRelinearizer`]. Native gadget keys also support key switching and
//! encrypted automorphisms at each prepared level. Ordinary requests use
//! [`BfvMultiplication`] to prepare multiplication and relinearization together,
//! deriving the level from the key and reusing all intermediate storage.
//! [`BfvMultiplication::try_with_backend`] additionally selects HPSPOVERQ,
//! whose one-sided P/Q scaling has an explicit bounded residual and centered
//! wrap correction. Its computation-only basis follows its own arithmetic
//! budget; it does not inherit the exact backend's P>NQ requirement.

#![deny(missing_docs)]

mod ciphertext;
mod client;
mod context;
mod evaluation_key;
mod evaluator;
mod modulus_switch;
mod multiplication;
mod multiply;
mod parameters;
mod public_key;
mod quadratic;
mod secret_key;
mod workspace;

pub use ciphertext::BfvCiphertext;
pub use client::BfvClient;
pub use context::{BfvContext, BfvContextError};
pub use evaluation_key::{
    BfvAutomorphism, BfvAutomorphismKey, BfvEvaluationKeyError, BfvKeySwitcher, BfvKeySwitchingKey,
    BfvRelinearizationKey, BfvRelinearizer,
};
pub use evaluator::BfvEvaluator;
pub use modulus_switch::{BfvModulusSwitch, BfvModulusSwitchError};
pub use multiplication::{BfvMultiplication, BfvMultiplicationBackend};
pub use multiply::{BfvMultiplier, BfvMultiplyError};
pub use parameters::{BfvParameters, BfvParametersError};
pub use primus_encoding::PlaintextEmbedding;
pub use public_key::{BfvPublicKey, BfvPublicKeyEncryptor};
pub use quadratic::BfvQuadraticCiphertext;
pub use secret_key::BfvSecretKeyContext;
pub use workspace::BfvDecryptWorkspace;

pub use evaluation_key::{
    BfvCollectiveAggregate, BfvCollectiveAutomorphismKey, BfvCollectiveContribution,
    BfvCollectiveError, BfvCollectivePublicKey, BfvCollectiveRelinearization,
    BfvCollectiveRelinearizationRound1, BfvCollectiveRelinearizationState,
    BfvCollectiveSwitchingKey, BfvFreshLookup, BfvFreshLookupKey, BfvRawQuadraticAggregate,
};

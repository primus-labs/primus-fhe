//! Per-owner collective key generation. Public masks and contributions are
//! mathematical messages; authentication, roster uniqueness and session IDs
//! belong to the calling protocol. No production operation constructs Σs_i.
//!
//! Individual imported shares must actually follow CBD1 for the stated
//! distribution contract; a secret's distribution metadata cannot prove this.
//! Native shares must use the plan context's actual NTT convention. Matching
//! geometry and ordered Q are checked before sampling, but do not prove the
//! secret's NTT or sampling provenance.
//! Setup masks are public uniform common randomness, independent of private
//! errors. Checked import validates canonical geometry, not provenance.

mod contribution;
mod evaluation_setup;
mod linear;
mod lookup;
mod public_key;
mod relinearization;
mod share;

pub use contribution::{BfvCollectiveAggregate, BfvCollectiveContribution};
pub use linear::{BfvCollectiveAutomorphismKey, BfvCollectiveSwitchingKey};
pub use lookup::{BfvFreshLookup, BfvFreshLookupKey, BfvRawQuadraticAggregate};
pub use public_key::BfvCollectivePublicKey;
pub use relinearization::{
    BfvCollectiveLookup, BfvCollectiveLookupRound1, BfvCollectiveRelinearization,
    BfvCollectiveRelinearizationRound1, BfvCollectiveRelinearizationState, BfvCollectiveSquare,
    BfvCollectiveSquareRound1,
};
pub use share::raw_unflooded_partial_phase_to;

use super::BfvEvaluationKeyError;

/// A malformed collective message, incompatible owner or incomplete aggregate.
#[derive(Debug, thiserror::Error)]
pub enum BfvCollectiveError {
    /// Evaluation-key parameters are invalid.
    #[error(transparent)]
    Evaluation(#[from] BfvEvaluationKeyError),
    /// This first collective construction requires exact CBD1/CBD21 sampling.
    #[error("collective BFV requires CBD1 secrets and CBD21 errors")]
    Distribution,
    /// The owner/message was bound to another actual context or setup instance.
    #[error("collective BFV setup or context mismatch")]
    Binding,
    /// A payload has an incomplete length or noncanonical residue.
    #[error("invalid collective BFV canonical payload")]
    Payload,
    /// The expected nonzero number of contributions has not been received.
    #[error("incomplete or overfull collective BFV aggregate")]
    Count,
    /// A complete first round has already claimed this local lookup setup.
    #[error("collective BFV lookup setup was already frozen")]
    ConsumedLookupSetup,
    /// An embedded target must have exactly half the destination ring length.
    #[error("invalid collective BFV own-share embedding")]
    Embedding,
}

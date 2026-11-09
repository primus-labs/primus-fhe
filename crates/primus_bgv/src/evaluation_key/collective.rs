//! Collective arithmetic over independently owned native shares.
//!
//! Public payloads carry local plan/round bindings. Authentication, roster
//! completeness and single-use policy belong to the calling protocol. The
//! collective key plans check the complete share geometry, ordered Q and
//! declared CBD1 law. Actual share randomness and NTT provenance are caller
//! contracts.

use primus_glwe_rns::DcrtGlweSecretKey;

mod common_mask;
mod key_plan;
mod linear;
mod messages;
mod partial_phase;
mod relinearization;

pub use common_mask::{BgvCollectivePublicKey, BgvSeededInput};
pub use linear::{BgvCollectiveAutomorphismKey, BgvCollectiveSwitchingKey};
pub use messages::{BgvCollectiveAggregate, BgvCollectiveContribution, BgvCollectiveError};
pub use partial_phase::raw_unflooded_partial_phase_to;
pub use relinearization::{
    BgvCollectiveRelinearization, BgvCollectiveRelinearizationState, BgvCollectiveRoundOne,
};

fn secret_prefix(share: &DcrtGlweSecretKey<u64>, len: usize) -> &[u64] {
    &share.iter_dcrt_poly().next().expect("rank-one secret").0[..len]
}

#[cfg(test)]
mod tests;

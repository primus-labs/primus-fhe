//! Coefficient selectors and bucket aggregation for sparse NTRU PBS.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

pub(crate) use blind_rotation::{
    AggregationWorkspace, SplitAggregationWorkspace, rotate_buckets, rotate_buckets_pair,
    rotate_groups, rotate_groups_split,
};
pub use primus_tfhe_ntru::SparseNtruBootstrappingKey;

pub use blind_rotation::SparseBlindRotationPairWorkspace;

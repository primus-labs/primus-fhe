//! Coefficient selectors and bucket aggregation for sparse NTRU PBS.

mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

pub(crate) use blind_rotation::{
    AggregationWorkspace, rotate_buckets, rotate_buckets_pair, rotate_groups, rotate_groups_pair,
};
pub use primus_tfhe_ntru::SparseNtruBootstrappingKey;

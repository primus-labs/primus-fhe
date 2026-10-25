//! Coefficient selectors and bucket aggregation for sparse NTRU PBS.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

pub(crate) use blind_rotation::{SparseWorkspace, rotate_buckets, rotate_buckets_pair};
pub use primus_tfhe_ntru::SparseNtruBootstrappingKey;

pub use blind_rotation::SparseBlindRotationPairWorkspace;

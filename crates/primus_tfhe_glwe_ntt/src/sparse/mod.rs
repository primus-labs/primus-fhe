//! Sparse key generation and blind rotation for the NTT backend.

pub(crate) mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use blind_rotation::ControlAggregationWorkspace;
pub(crate) use key::{SparseKeyLayout, generate_with_layout};

pub use blind_rotation::{SparseGlweBlindRotationBatchWorkspace, SparseGlweBlindRotationWorkspace};
pub use primus_tfhe_glwe::SparseGlweBootstrappingKey;

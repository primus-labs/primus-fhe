//! Sparse key generation and blind rotation for the NTT backend.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::{SparseKeyLayout, generate_with_layout};

pub use blind_rotation::{SparseGlweBlindRotationBatchWorkspace, SparseGlweBlindRotationWorkspace};
pub use primus_tfhe_glwe::SparseGlweBootstrappingKey;

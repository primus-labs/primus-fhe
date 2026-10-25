//! Sparse keys and coefficient-aggregation blind rotation for the Fourier backend.

mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

pub use blind_rotation::SparseGlweBlindRotationWorkspace;
pub use primus_tfhe_glwe::SparseGlweBootstrappingKey;

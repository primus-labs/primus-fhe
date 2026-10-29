//! Direct blind rotation for contiguous block-binary LWE secrets.
//!
//! Each block stores its bit controls and, only for AtMostOne, an independent dummy.
//! Coefficient aggregation uses no bucket map or matching.

mod blind_rotation;
mod key;

pub use blind_rotation::BlockGlweBlindRotationWorkspace;
pub(crate) use key::BlockKeyLayout;
pub use primus_tfhe_glwe::BlockGlweBootstrappingKey;

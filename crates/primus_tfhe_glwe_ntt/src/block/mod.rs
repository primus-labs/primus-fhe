//! Direct blind rotation for contiguous block-binary LWE secrets.
//!
//! Each block contributes its bit controls, with an independent dummy only for
//! AtMostOne, followed by one external product.

mod aggregation;
mod blind_rotation;
mod key;

pub use blind_rotation::{BlockGlweBlindRotationBatchWorkspace, BlockGlweBlindRotationWorkspace};
pub(crate) use key::{generate_with_layout, validate_secret};
pub use primus_tfhe_glwe::BlockGlweBootstrappingKey;

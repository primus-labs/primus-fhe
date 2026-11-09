//! Direct blind rotation for contiguous block-binary LWE secrets.
//!
//! Each block contributes its bit controls, with an independent dummy only for
//! AtMostOne, followed by one external product. No bucket map or matching is used.

mod blind_rotation;
mod key;

pub use blind_rotation::{BlockGlweBlindRotationBatchWorkspace, BlockGlweBlindRotationWorkspace};
pub(crate) use key::{BlockKeyLayout, generate_validated_with_layout, generate_with_layout};
pub use primus_tfhe_glwe::BlockGlweBootstrappingKey;

//! Contiguous direct block controls with first-block public-LUT lifting.

mod blind_rotation;
mod key;

pub(crate) use blind_rotation::{AggregationWorkspace, rotate_blocks, rotate_blocks_pair};
pub use primus_tfhe_ntru::BlockNtruBootstrappingKey;

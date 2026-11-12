//! Contiguous exact native controls with first-block public-LUT lifting.

mod blind_rotation;
mod key;

pub(crate) use blind_rotation::{
    AggregationWorkspace, SplitAggregationWorkspace, rotate_blocks, rotate_blocks_pair,
    rotate_blocks_split, rotate_blocks_split_pair,
};
pub use primus_tfhe_ntru::BlockNtruBootstrappingKey;

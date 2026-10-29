//! Contiguous exact native controls with first-block public-LUT lifting.

mod blind_rotation;
mod key;

pub(crate) use blind_rotation::{rotate_blocks, rotate_blocks_split};
pub(crate) use key::BlockKeyLayout;
pub use primus_tfhe_ntru::BlockNtruBootstrappingKey;

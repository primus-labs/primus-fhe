use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Define the Hash trait
pub trait Hash: Debug + Clone + Default + Sized {
    /// output
    type Output: Clone
        + Copy
        + PartialEq
        + Default
        + Debug
        + Sized
        + AsRef<[u8]>
        + Serialize
        + for<'de> Deserialize<'de>
        + Sync
        + Send;

    /// Create a new instance.
    fn new() -> Self {
        Self::default()
    }

    /// Update with input
    fn update_hash_value(&mut self, input: &[u8]);

    /// Output a hash value and reset
    fn output_reset(&mut self) -> Self::Output;
}

impl Hash for Sha256 {
    type Output = [u8; 32];

    #[inline]
    fn update_hash_value(&mut self, input: &[u8]) {
        self.update(input);
    }

    #[inline]
    fn output_reset(&mut self) -> Self::Output {
        self.finalize_reset().into()
    }
}

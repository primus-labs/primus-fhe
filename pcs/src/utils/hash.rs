use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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
        + for<'de> Deserialize<'de>;

    /// Create a new instance.
    fn new() -> Self {
        Self::default()
    }

    /// Update with input
    fn update_hash_value(&mut self, input: &[u8]);

    /// Update with a string as input
    fn update_string(&mut self, input: String);

    /// Uutput a hash value and reset
    fn output_reset(&mut self) -> Self::Output;
}

impl Hash for Sha3_256 {
    type Output = [u8; 32];

    fn update_hash_value(&mut self, hashed: &[u8]) {
        self.update(hashed);
    }

    fn update_string(&mut self, hashed: String) {
        self.update(hashed);
    }

    fn output_reset(&mut self) -> Self::Output {
        self.finalize_reset().into()
    }
}

use std::fmt::Debug;

use sha3::{Digest, Sha3_256};

/// Hash
pub trait Hash: Debug + Clone + Default + Sized {
    /// output
    type Output: Clone + Copy + PartialEq + Default + Debug + Sized + AsRef<[u8]>;

    /// new
    fn new() -> Self {
        Self::default()
    }

    /// update with a hash value as input
    fn update_hash_value(&mut self, input: &[u8]);

    /// update with a string as input
    fn update_string(&mut self, input: String);

    /// output a hash value and reset
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

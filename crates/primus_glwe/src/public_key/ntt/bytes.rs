//! Native-endian public-key serialization.

use super::NttGlwePublicKey;
use crate::NttGlweCiphertext;
use primus_data::{Data, DataMut, DataOwned};
use primus_integer::FheUint;

impl<S, T> NttGlwePublicKey<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a public key from its native-endian byte representation.
    #[inline]
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            key: NttGlweCiphertext::from_bytes(data),
        }
    }
}

impl<S, T> NttGlwePublicKey<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Replaces this public key from its native-endian byte representation.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }
}

impl<S, T> NttGlwePublicKey<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Converts this public key to native-endian bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    /// Writes this public key as native-endian bytes into `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the byte length of this public key.
    #[inline]
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
    }
}

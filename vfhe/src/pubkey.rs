use algebra::ring::Ring;

use crate::Ciphertext;

/// public key
#[derive(Debug, Clone)]
pub struct PublicKey<R: Ring> {
    data: Vec<Ciphertext<R>>,
}

impl<R: Ring> From<Vec<Ciphertext<R>>> for PublicKey<R> {
    #[inline]
    fn from(value: Vec<Ciphertext<R>>) -> Self {
        Self { data: value }
    }
}

impl<R: Ring> Default for PublicKey<R> {
    #[inline]
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<R: Ring> PublicKey<R> {
    /// Creates a new [`PublicKey<R>`].
    #[inline]
    pub fn new(data: Vec<Ciphertext<R>>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`PublicKey<R>`].
    #[inline]
    pub fn data(&self) -> &[Ciphertext<R>] {
        self.data.as_ref()
    }
}

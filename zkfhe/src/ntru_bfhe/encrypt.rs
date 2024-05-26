//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, NTRUSecretKeyPack};

/// Encryptor
pub struct Encryptor<F: NTTField> {
    sk: NTRUSecretKeyPack<F>,
}

impl<F: NTTField> Encryptor<F> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(sk: NTRUSecretKeyPack<F>) -> Self {
        Self { sk }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt(&self, m: bool) -> LWECiphertext {
        self.sk.encrypt(m)
    }
}

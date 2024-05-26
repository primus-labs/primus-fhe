//! implementation of decryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, SecretKeyPack};

/// Encryptor
pub struct Decryptor<F: NTTField> {
    sk: SecretKeyPack<F>,
}

impl<F: NTTField> Decryptor<F> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<F>) -> Self {
        Self { sk }
    }

    /// Decrypt a ciphertext into a bool message.
    #[inline]
    pub fn decrypt(&self, c: &LWECiphertext) -> bool {
        self.sk.decrypt(c)
    }

    /// Decrypt a ciphertext into a bool message and an error.
    #[inline]
    pub fn decrypt_with_noise(&self, c: &LWECiphertext) -> (bool, LWEModulusType) {
        self.sk.decrypt_with_noise(c)
    }
}

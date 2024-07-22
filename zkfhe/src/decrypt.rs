//! implementation of decryption.

use algebra::NTTField;
use fhe_core::{LWECipherValueContainer, LWECiphertext, LWEPlainContainer, SecretKeyPack};

/// Encryptor
pub struct Decryptor<M: LWEPlainContainer, C: LWECipherValueContainer, F: NTTField> {
    sk: SecretKeyPack<M, C, F>,
}

impl<M: LWEPlainContainer, C: LWECipherValueContainer, F: NTTField> Decryptor<M, C, F> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<M, C, F>) -> Self {
        Self { sk }
    }

    /// Decrypt a ciphertext into a message.
    #[inline]
    pub fn decrypt(&self, c: &LWECiphertext<C>) -> M {
        self.sk.decrypt(c)
    }

    /// Decrypt a ciphertext into a bool message and an error.
    #[inline]
    pub fn decrypt_with_noise(&self, c: &LWECiphertext<C>) -> (M, C) {
        self.sk.decrypt_with_noise(c)
    }
}

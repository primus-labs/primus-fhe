//! implementation of decryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Decryptor<C: LWEModulusType, F: NTTField> {
    sk: SecretKeyPack<C, F>,
}

impl<C: LWEModulusType, F: NTTField> Decryptor<C, F> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<C, F>) -> Self {
        Self { sk }
    }

    /// Decrypt a ciphertext into a message.
    #[inline]
    pub fn decrypt<M: LWEMsgType>(&self, c: &LWECiphertext<C>) -> M {
        self.sk.decrypt(c)
    }

    /// Decrypt a ciphertext into a bool message and an error.
    #[inline]
    pub fn decrypt_with_noise<M: LWEMsgType>(&self, c: &LWECiphertext<C>) -> (M, C) {
        self.sk.decrypt_with_noise(c)
    }
}

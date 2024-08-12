//! implementation of decryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Decryptor<C: LWEModulusType, Q: NTTField, Qks: NTTField> {
    sk: SecretKeyPack<C, Q, Qks>,
}

impl<C: LWEModulusType, Q: NTTField, Qks: NTTField> Decryptor<C, Q, Qks> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<C, Q, Qks>) -> Self {
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

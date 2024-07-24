//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Encryptor<C: LWEModulusType, F: NTTField> {
    sk: SecretKeyPack<C, F>,
}

impl<C: LWEModulusType, F: NTTField> Encryptor<C, F> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<C, F>) -> Self {
        Self { sk }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt<M: LWEMsgType>(&self, m: M) -> LWECiphertext<C> {
        self.sk.encrypt(m)
    }
}

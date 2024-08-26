//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Encryptor<C: LWEModulusType, Q: NTTField> {
    sk: SecretKeyPack<C, Q>,
}

impl<C: LWEModulusType, Q: NTTField> Encryptor<C, Q> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<C, Q>) -> Self {
        Self { sk }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt<M: LWEMsgType>(&self, m: M) -> LWECiphertext<C> {
        self.sk.encrypt(m)
    }
}

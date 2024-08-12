//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Encryptor<C: LWEModulusType, Q: NTTField, Qks: NTTField> {
    sk: SecretKeyPack<C, Q, Qks>,
}

impl<C: LWEModulusType, Q: NTTField, Qks: NTTField> Encryptor<C, Q, Qks> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<C, Q, Qks>) -> Self {
        Self { sk }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt<M: LWEMsgType>(&self, m: M) -> LWECiphertext<C> {
        self.sk.encrypt(m)
    }
}

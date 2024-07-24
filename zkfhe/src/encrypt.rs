//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECiphertext, LWEModulusType, LWEMsgType, SecretKeyPack};

/// Encryptor
pub struct Encryptor<M: LWEMsgType, C: LWEModulusType, F: NTTField> {
    sk: SecretKeyPack<M, C, F>,
}

impl<M: LWEMsgType, C: LWEModulusType, F: NTTField> Encryptor<M, C, F> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(sk: SecretKeyPack<M, C, F>) -> Self {
        Self { sk }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt(&self, m: M) -> LWECiphertext<C> {
        self.sk.encrypt(m)
    }
}

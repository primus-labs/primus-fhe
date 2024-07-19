//! implementation of encryption.

use algebra::NTTField;
use fhe_core::{LWECipherContainer, LWECiphertext, LWEPlainContainer, SecretKeyPack};

/// Encryptor
pub struct Encryptor<M: LWEPlainContainer<C>, C: LWECipherContainer, F: NTTField> {
    sk: SecretKeyPack<M, C, F>,
}

impl<M: LWEPlainContainer<C>, C: LWECipherContainer, F: NTTField> Encryptor<M, C, F> {
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

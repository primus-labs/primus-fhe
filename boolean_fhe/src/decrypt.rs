use algebra::{integer::UnsignedInteger, reduce::RingReduce, NttField};
use fhe_core::{LweCiphertext, LweParameters, LweSecretKey};

use crate::SecretKeyPack;

/// Encryptor
pub struct Decryptor<C: UnsignedInteger, LweModulus: RingReduce<C>> {
    lwe_secret_key: LweSecretKey<C>,
    params: LweParameters<C, LweModulus>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>> Decryptor<C, LweModulus> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new<Q: NttField>(sk: &SecretKeyPack<C, LweModulus, Q>) -> Self {
        Self {
            lwe_secret_key: sk.lwe_secret_key().clone(),
            params: *sk.lwe_params(),
        }
    }

    /// Decrypt a ciphertext into a message.
    #[inline]
    pub fn decrypt<M>(&self, cipher_text: &LweCiphertext<C>) -> M
    where
        M: TryFrom<C>,
    {
        self.lwe_secret_key.decrypt(cipher_text, &self.params)
    }

    /// Decrypt a ciphertext into a bool message and an error.
    #[inline]
    pub fn decrypt_with_noise<M>(&self, cipher_text: &LweCiphertext<C>) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        self.lwe_secret_key
            .decrypt_with_noise(cipher_text, &self.params)
    }
}

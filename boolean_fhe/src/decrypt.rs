use algebra::{integer::UnsignedInteger, reduce::RingReduce, NttField};
use fhe_core::{LweCiphertext, LweParameters, LweSecretKey};

use crate::SecretKeyPack;

/// Encryptor
pub struct Decryptor<C: UnsignedInteger> {
    lwe_secret_key: LweSecretKey<C>,
    params: LweParameters<C>,
}

impl<C: UnsignedInteger> Decryptor<C> {
    /// Create a Decryptor instance.
    #[inline]
    pub fn new<Q: NttField>(sk: &SecretKeyPack<C, Q>) -> Self {
        Self {
            lwe_secret_key: sk.lwe_secret_key().clone(),
            params: *sk.lwe_params(),
        }
    }

    /// Decrypt a ciphertext into a message.
    #[inline]
    pub fn decrypt<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        cipher_modulus: impl RingReduce<C>,
    ) -> M
    where
        M: TryFrom<C>,
    {
        self.lwe_secret_key
            .decrypt(cipher_text, &self.params, cipher_modulus)
    }

    /// Decrypt a ciphertext into a bool message and an error.
    #[inline]
    pub fn decrypt_with_noise<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        cipher_modulus: impl RingReduce<C>,
    ) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        self.lwe_secret_key
            .decrypt_with_noise(cipher_text, &self.params, cipher_modulus)
    }
}

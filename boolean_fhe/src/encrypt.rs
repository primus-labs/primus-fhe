use algebra::{integer::UnsignedInteger, reduce::RingReduce, NttField};
use fhe_core::{LweCiphertext, LweParameters, LweSecretKey};

use crate::SecretKeyPack;

/// Encryptor
pub struct Encryptor<C: UnsignedInteger, LweModulus: RingReduce<C>> {
    lwe_secret_key: LweSecretKey<C>,
    params: LweParameters<C, LweModulus>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>> Encryptor<C, LweModulus> {
    /// New a Encryptor instance.
    #[inline]
    pub fn new<Q: NttField>(sk: &SecretKeyPack<C, LweModulus, Q>) -> Self {
        Self {
            lwe_secret_key: sk.lwe_secret_key().clone(),
            params: *sk.lwe_params(),
        }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt<M, R>(&self, message: M, rng: &mut R) -> LweCiphertext<C>
    where
        M: TryInto<C>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.lwe_secret_key.encrypt(message, &self.params, rng)
    }
}

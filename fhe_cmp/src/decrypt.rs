use algebra::{integer::UnsignedInteger, reduce::RingReduce, AsInto, NttField};
use fhe_core::{decode, encode, LweCiphertext, LweParameters, LweSecretKey};

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

    /// Decrypt a ciphertext into message and an error.
    #[inline]
    pub fn decrypt_with_noise<M>(&self, cipher_text: &LweCiphertext<C>) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        self.lwe_secret_key
            .decrypt_with_noise(cipher_text, &self.params)
    }

    #[inline]
    pub fn decrypt_custom<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        cipher_modulus: impl RingReduce<C>,
        plain_modulus_bits: u32,
    ) -> M
    where
        M: TryFrom<C>,
    {
        let a_mul_s = cipher_modulus.reduce_dot_product(cipher_text.a(), &self.lwe_secret_key);
        let plaintext = cipher_modulus.reduce_sub(cipher_text.b(), a_mul_s);
        let plain_modulus_value = 1u64 << plain_modulus_bits;
        let t: C = plain_modulus_value.as_into();
        decode(plaintext, t, self.params.cipher_modulus_value)
    }
    #[inline]
    pub fn decrypt_custom_noise<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        cipher_modulus: impl RingReduce<C>,
        plain_modulus_bits: u32,
    ) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        let plain_modulus_value = 1u64 << plain_modulus_bits;
        let t: C = plain_modulus_value.as_into();
        let a_mul_s = cipher_modulus.reduce_dot_product(cipher_text.a(), &self.lwe_secret_key);
        let plaintext = cipher_modulus.reduce_sub(cipher_text.b(), a_mul_s);
        let q = self.params.cipher_modulus_value;
        let message = decode(plaintext, t, q);
        let fresh = encode(message, t, q);

        (
            message,
            cipher_modulus
                .reduce_sub(plaintext, fresh)
                .min(cipher_modulus.reduce_sub(fresh, plaintext)),
        )
    }
}

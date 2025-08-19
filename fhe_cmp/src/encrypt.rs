use crate::SecretKeyPack;
use algebra::{integer::UnsignedInteger, reduce::RingReduce, AsInto, NttField};
use fhe_core::{encode, LweCiphertext, LweParameters, LweSecretKey};

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

    /// Encrypt message.
    #[inline]
    pub fn encrypt<M, R>(
        &self,
        message: M,
        cipher_modulus: impl RingReduce<C>,
        rng: &mut R,
        plain_modulus_bits: u32,
    ) -> LweCiphertext<C>
    where
        M: TryInto<C>,
        R: rand::Rng + rand::CryptoRng,
    {
        let gaussian = self.params.noise_distribution();
        let mut ciphertext = LweCiphertext::generate_random_zero_sample(
            self.lwe_secret_key.as_ref(),
            cipher_modulus,
            &gaussian,
            rng,
        );
        let plain_modulus_value: C = (1u64 << plain_modulus_bits).as_into();
        cipher_modulus.reduce_add_assign(
            ciphertext.b_mut(),
            encode(
                message,
                plain_modulus_value,
                self.params.cipher_modulus_value,
            ),
        );

        ciphertext
    }
}

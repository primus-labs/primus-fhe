use algebra::modulus::BarrettModulus;
use fhe_core::{LweCiphertext, LweParameters, LwePublicKey};

/// Encryptor
pub struct Encryptor {
    lwe_public_key: LwePublicKey<u64>,
    params: LweParameters<u64, BarrettModulus<u64>>,
}

impl Encryptor {
    /// New a Encryptor instance.
    #[inline]
    pub fn new(
        lwe_public_key: LwePublicKey<u64>,
        params: LweParameters<u64, BarrettModulus<u64>>,
    ) -> Self {
        Self {
            lwe_public_key,
            params,
        }
    }

    /// Encrypt a bool message.
    #[inline]
    pub fn encrypt<R>(&self, message: u64, rng: &mut R) -> LweCiphertext<u64>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.lwe_public_key.encrypt(message, &self.params, rng)
    }
}

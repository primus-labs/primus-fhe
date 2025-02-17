use std::sync::Arc;

use algebra::{integer::UnsignedInteger, reduce::RingReduce, NttField};
use fhe_core::{LweSecretKey, NttRlweSecretKey, RingSecretKeyType, RlweSecretKey};
use rand::{CryptoRng, Rng};

use crate::{parameter::Steps, BooleanFheParameters};

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    /// LWE secret key
    lwe_secret_key: LweSecretKey<C>,
    /// rlwe secret key
    rlwe_secret_key: RlweSecretKey<Q>,
    /// ntt version rlwe secret key
    ntt_rlwe_secret_key: NttRlweSecretKey<Q>,
    /// FHE parameters
    parameters: BooleanFheParameters<C, LweModulus, Q>,
    ntt_table: Arc<<Q as NttField>::Table>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> SecretKeyPack<C, LweModulus, Q> {
    /// Creates a new [`SecretKeyPack<C, Q>`].
    pub fn new<R>(parameters: BooleanFheParameters<C, LweModulus, Q>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let lwe_secret_key = LweSecretKey::generate(parameters.lwe_params(), rng);

        let ring_dimension = parameters.ring_dimension();

        let rlwe_secret_key = match parameters.steps() {
            Steps::BrMsKs => RlweSecretKey::generate(
                parameters.ring_secret_key_type(),
                ring_dimension,
                None,
                rng,
            ),
            Steps::BrKsRlevMs | Steps::BrKsLevMs => RlweSecretKey::generate(
                parameters.ring_secret_key_type(),
                ring_dimension,
                Some(parameters.ring_noise_distribution()),
                rng,
            ),
            Steps::BrMs => {
                assert!(
                    parameters.ring_secret_key_type() == RingSecretKeyType::Binary
                        || parameters.ring_secret_key_type() == RingSecretKeyType::Ternary
                );
                assert_eq!(parameters.lwe_dimension(), parameters.ring_dimension());
                RlweSecretKey::from_lwe_secret_key(&lwe_secret_key)
            }
        };

        let ntt_table = parameters.generate_ntt_table_for_rlwe();

        let ntt_rlwe_secret_key =
            NttRlweSecretKey::from_coeff_secret_key(&rlwe_secret_key, &ntt_table);

        Self {
            lwe_secret_key,
            rlwe_secret_key,
            ntt_rlwe_secret_key,
            parameters,
            ntt_table: Arc::new(ntt_table),
        }
    }

    /// Returns a reference to the parameters of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn parameters(&self) -> &BooleanFheParameters<C, LweModulus, Q> {
        &self.parameters
    }

    /// Returns a reference to the lwe secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &LweSecretKey<C> {
        &self.lwe_secret_key
    }

    /// Returns a reference to the rlwe secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn rlwe_secret_key(&self) -> &RlweSecretKey<Q> {
        &self.rlwe_secret_key
    }

    /// Returns a reference to the ntt rlwe secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn ntt_rlwe_secret_key(&self) -> &NttRlweSecretKey<Q> {
        &self.ntt_rlwe_secret_key
    }

    /// Returns a reference to the ntt table of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn ntt_table(&self) -> &Arc<<Q as NttField>::Table> {
        &self.ntt_table
    }

    /// Returns a reference to the lwe params of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn lwe_params(&self) -> &fhe_core::LweParameters<C, LweModulus> {
        self.parameters.lwe_params()
    }

    /// Encrypts a message with cipher modulus and random number generator.
    #[inline]
    pub fn encrypt<M, R>(&self, message: M, rng: &mut R) -> fhe_core::LweCiphertext<C>
    where
        M: TryInto<C>,
        R: Rng + CryptoRng,
    {
        self.lwe_secret_key.encrypt(message, self.lwe_params(), rng)
    }

    /// Decrypts the cipher text.
    #[inline]
    pub fn decrypt<M>(&self, cipher_text: &fhe_core::LweCiphertext<C>) -> M
    where
        M: TryFrom<C>,
    {
        self.lwe_secret_key.decrypt(cipher_text, self.lwe_params())
    }

    /// Decrypts the cipher text and calculates the noise.
    #[inline]
    pub fn decrypt_with_noise<M>(&self, cipher_text: &fhe_core::LweCiphertext<C>) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        self.lwe_secret_key
            .decrypt_with_noise(cipher_text, self.lwe_params())
    }
}

use algebra::{NTTField, NTTPolynomial, Polynomial};
use lattice::{sample_binary_values, sample_ternary_values};
use rand::{CryptoRng, Rng};

use crate::{
    ciphertext::LWECiphertext, decode, encode, parameter::LWEParameters, LWEModulusType,
    LWEMsgType, Parameters, Steps,
};

/// The distribution type of the LWE Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum LWESecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
}

/// The distribution type of the Ring Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum RingSecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
    /// Gaussian SecretKey Distribution.
    Gaussian,
}

/// Ring Secret key
pub type RingSecretKey<F> = Polynomial<F>;

/// NTT version Ring Secret key
pub type NTTRingSecretKey<F> = NTTPolynomial<F>;

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<C: LWEModulusType, Q: NTTField> {
    /// LWE secret key
    lwe_secret_key: Vec<C>,

    /// ring secret key
    ring_secret_key: RingSecretKey<Q>,
    /// ntt version ring secret key
    ntt_ring_secret_key: NTTRingSecretKey<Q>,
    /// FHE parameters
    parameters: Parameters<C, Q>,
}

impl<C: LWEModulusType, Q: NTTField> SecretKeyPack<C, Q> {
    fn create_lwe_secret_key<R: Rng + CryptoRng>(
        params: &LWEParameters<C>,
        csrng: &mut R,
    ) -> Vec<C> {
        match params.secret_key_type {
            LWESecretKeyType::Binary => sample_binary_values(params.dimension, csrng),
            LWESecretKeyType::Ternary => {
                sample_ternary_values(params.cipher_modulus, params.dimension, csrng)
            }
        }
    }

    /// Creates a new [`SecretKeyPack<C, Q>`].
    pub fn new<R: Rng + CryptoRng>(params: Parameters<C, Q>, csrng: &mut R) -> Self {
        let lwe_secret_key = Self::create_lwe_secret_key(&params.lwe_params(), csrng);

        let ring_dimension = params.ring_dimension();

        let ring_secret_key = match params.steps() {
            Steps::BrMsKs => match params.ring_secret_key_type() {
                RingSecretKeyType::Binary => Polynomial::random_with_binary(ring_dimension, csrng),
                RingSecretKeyType::Ternary => {
                    Polynomial::random_with_ternary(ring_dimension, csrng)
                }
                RingSecretKeyType::Gaussian => unimplemented!(),
            },
            Steps::BrKsMs => match params.ring_secret_key_type() {
                RingSecretKeyType::Binary => Polynomial::random_with_binary(ring_dimension, csrng),
                RingSecretKeyType::Ternary => {
                    Polynomial::random_with_ternary(ring_dimension, csrng)
                }
                RingSecretKeyType::Gaussian => Polynomial::random_with_gaussian(
                    ring_dimension,
                    csrng,
                    params.ring_noise_distribution(),
                ),
            },
            Steps::BrMs => {
                assert!(
                    params.ring_secret_key_type() == RingSecretKeyType::Binary
                        || params.ring_secret_key_type() == RingSecretKeyType::Ternary
                );
                assert_eq!(params.lwe_dimension(), params.ring_dimension());
                // conversion
                let convert = |v: &C| {
                    if v.is_zero() {
                        Q::zero()
                    } else if v.is_one() {
                        Q::one()
                    } else {
                        Q::neg_one()
                    }
                };

                // s = [s_0, s_1,..., s_{n-1}]
                <Polynomial<Q>>::new(lwe_secret_key.iter().map(convert).collect())
            }
        };
        let ntt_ring_secret_key = ring_secret_key.clone().into_ntt_polynomial();

        Self {
            lwe_secret_key,
            ring_secret_key,
            ntt_ring_secret_key,
            parameters: params,
        }
    }

    /// Returns the lwe secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[C] {
        &self.lwe_secret_key
    }

    /// Returns the ring secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn ring_secret_key(&self) -> &RingSecretKey<Q> {
        &self.ring_secret_key
    }

    /// Returns the ntt ring secret key of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn ntt_ring_secret_key(&self) -> &NTTRingSecretKey<Q> {
        &self.ntt_ring_secret_key
    }

    /// Returns the parameters of this [`SecretKeyPack<C, Q>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<C, Q> {
        &self.parameters
    }

    /// Encrypts message into [`LWECiphertext`].
    #[inline]
    pub fn encrypt<M: LWEMsgType, R: Rng + CryptoRng>(
        &self,
        message: M,
        csrng: &mut R,
    ) -> LWECiphertext<C> {
        let cipher_modulus = self.parameters.lwe_cipher_modulus();
        let cipher_modulus_value = self.parameters.lwe_cipher_modulus_value();
        let noise_distribution = self.parameters.lwe_noise_distribution();

        let mut ciphertext = LWECiphertext::generate_random_zero_sample(
            self.lwe_secret_key(),
            cipher_modulus_value,
            cipher_modulus,
            noise_distribution,
            csrng,
        );

        ciphertext.b_mut().add_reduce_assign(
            encode(
                message,
                self.parameters.lwe_plain_modulus(),
                cipher_modulus_value.as_into(),
            ),
            cipher_modulus,
        );

        ciphertext
    }

    /// Decrypts the [`LWECiphertext`] back to message.
    #[inline]
    pub fn decrypt<M: LWEMsgType>(&self, cipher_text: &LWECiphertext<C>) -> M {
        let cipher_modulus = self.parameters.lwe_cipher_modulus();

        let a_mul_s = C::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), cipher_modulus);
        let plaintext = cipher_text.b().sub_reduce(a_mul_s, cipher_modulus);

        decode(
            plaintext,
            self.parameters.lwe_plain_modulus(),
            self.parameters.lwe_cipher_modulus_value().as_into(),
        )
    }

    /// Decrypts the [`LWECiphertext`] back to message.
    #[inline]
    pub fn decrypt_with_noise<M: LWEMsgType>(&self, cipher_text: &LWECiphertext<C>) -> (M, C) {
        let cipher_modulus = self.parameters.lwe_cipher_modulus();
        let t: u64 = self.parameters.lwe_plain_modulus();
        let q: u64 = self.parameters.lwe_cipher_modulus_value().as_into();

        let a_mul_s = C::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), cipher_modulus);

        let plaintext = cipher_text.b().sub_reduce(a_mul_s, cipher_modulus);

        let message = decode(plaintext, t, q);

        let fresh = encode(message, t, q);

        (
            message,
            plaintext
                .sub_reduce(fresh, cipher_modulus)
                .min(fresh.sub_reduce(plaintext, cipher_modulus)),
        )
    }
}

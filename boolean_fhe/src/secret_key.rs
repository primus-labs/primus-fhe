use algebra::{NTTField, NTTPolynomial, Polynomial, RandomNTTField, RandomRing, Ring, RoundedDiv};
use lattice::dot_product;
use num_traits::{CheckedMul, One, Zero};
use rand::prelude::*;

use crate::{LWECiphertext, LWEPlaintext, Parameters};

/// The distribution type of the LWE Secret Key
#[derive(Debug, Clone, Copy)]
pub enum SecretKeyType {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    Ternary,
}

/// LWE Secret key
pub type LWESecretKey<R> = Vec<R>;

/// RLWE Secret key
pub type RLWESecretKey<F> = Polynomial<F>;

/// NTT version RLWE Secret key
pub type NTTRLWESecretKey<F> = NTTPolynomial<F>;

/// boolean fhe's secret keys pack
#[derive(Clone)]
pub struct SecretKeyPack<R: Ring, F: NTTField> {
    lwe_secret_key: LWESecretKey<R>,
    rlwe_secret_key: RLWESecretKey<F>,
    ntt_rlwe_secret_key: NTTRLWESecretKey<F>,
    parameters: Parameters<R, F>,
}

impl<R: Ring, F: NTTField> SecretKeyPack<R, F> {
    /// Returns the lwe secret key of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[R] {
        &self.lwe_secret_key
    }

    /// Returns the rlwe secret key of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn rlwe_secret_key(&self) -> &RLWESecretKey<F> {
        &self.rlwe_secret_key
    }

    /// Returns the ntt rlwe secret key of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn ntt_rlwe_secret_key(&self) -> &NTTRLWESecretKey<F> {
        &self.ntt_rlwe_secret_key
    }

    /// Returns the parameters of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<R, F> {
        &self.parameters
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt(&self, cipher_text: &LWECiphertext<R>) -> bool {
        let encoded_message =
            cipher_text.b() - dot_product(cipher_text.a(), self.lwe_secret_key.as_slice());
        decode(encoded_message, self.parameters.lwe_message_modulus())
    }
}

impl<R: RandomRing, F: NTTField> SecretKeyPack<R, F> {
    /// Encrypts [`LWEPlaintext`] into [`LWECiphertext<R>`].
    #[inline]
    pub fn encrypt<Rng>(&self, message: LWEPlaintext, mut rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let dis = R::standard_distribution();
        let lwe_dimension = self.parameters.lwe_dimension();
        let chi = self.parameters.lwe_noise_distribution();

        let a: Vec<R> = dis.sample_iter(&mut rng).take(lwe_dimension).collect();
        let b = dot_product(&a, self.lwe_secret_key.as_slice())
            + encode::<R>(message, self.parameters.lwe_message_modulus())
            + chi.sample(&mut rng);

        LWECiphertext::new(a, b)
    }
}

impl<R: RandomRing, F: RandomNTTField> SecretKeyPack<R, F> {
    /// Creates a new [`SecretKeyPack<R, F>`].
    pub fn new<Rng>(parameters: Parameters<R, F>, mut rng: Rng) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let lwe_dimension = parameters.lwe_dimension();
        let lwe_secret_key = match parameters.secret_key_type() {
            SecretKeyType::Binary => R::binary_distribution()
                .sample_iter(&mut rng)
                .take(lwe_dimension)
                .collect(),
            SecretKeyType::Ternary => R::ternary_distribution()
                .sample_iter(&mut rng)
                .take(lwe_dimension)
                .collect(),
        };

        let rlwe_dimension = parameters.rlwe_dimension();
        let rlwe_secret_key = Polynomial::random(rlwe_dimension, &mut rng);
        let ntt_rlwe_secret_key = rlwe_secret_key.clone().to_ntt_polynomial();

        Self {
            lwe_secret_key,
            rlwe_secret_key,
            ntt_rlwe_secret_key,
            parameters,
        }
    }
}

/// Encodes a message
#[inline]
fn encode<R: Ring>(message: LWEPlaintext, message_modulus: R::Inner) -> R {
    if message {
        R::from(R::modulus_value().rounded_div(message_modulus))
    } else {
        R::ZERO
    }
}

/// Decodes a cipher text
fn decode<R: Ring>(encoded_message: R, message_modulus: R::Inner) -> bool {
    let decoded = encoded_message
        .inner()
        .checked_mul(&message_modulus)
        .unwrap()
        .rounded_div(R::modulus_value());

    if decoded == message_modulus || decoded.is_zero() {
        false
    } else if decoded.is_one() {
        true
    } else {
        panic!("Wrong decoding output: {:?}", decoded);
    }
}

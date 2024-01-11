use std::cell::RefCell;

use algebra::{NTTField, NTTPolynomial, Polynomial, RandomNTTField, RandomRing, Ring, RoundedDiv};
use lattice::dot_product;
use num_traits::{CheckedMul, One, Zero};
use rand::prelude::*;
use rand_chacha::ChaCha12Rng;

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

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// RLWE secret key, ntt version RLWE secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<R: Ring, F: NTTField> {
    /// LWE secret key
    lwe_secret_key: LWESecretKey<R>,
    /// RLWE secret key
    rlwe_secret_key: RLWESecretKey<F>,
    /// ntt version RLWE secret key
    ntt_rlwe_secret_key: NTTRLWESecretKey<F>,
    /// boolean fhe's parameters
    parameters: Parameters<R, F>,
    /// cryptographically secure random number generator
    csrng: RefCell<ChaCha12Rng>,
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
        let encoded_message = cipher_text.b() - dot_product(cipher_text.a(), self.lwe_secret_key());
        decode(encoded_message)
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext<R>) -> (bool, R) {
        let encoded_message = cipher_text.b() - dot_product(cipher_text.a(), self.lwe_secret_key());
        let message = decode(encoded_message);

        let fresh = encode::<R>(message);
        (
            message,
            (encoded_message - fresh).min(fresh - encoded_message),
        )
    }

    /// Returns the csrng of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn csrng(&self) -> std::cell::Ref<'_, ChaCha12Rng> {
        self.csrng.borrow()
    }

    /// Returns the csrng of this [`SecretKeyPack<R, F>`].
    #[inline]
    pub fn csrng_mut(&self) -> std::cell::RefMut<'_, ChaCha12Rng> {
        self.csrng.borrow_mut()
    }
}

impl<R: RandomRing, F: NTTField> SecretKeyPack<R, F> {
    /// Encrypts [`LWEPlaintext`] into [`LWECiphertext<R>`].
    #[inline]
    pub fn encrypt(&self, message: LWEPlaintext) -> LWECiphertext<R> {
        let standard_distribution = R::standard_distribution();
        let lwe_dimension = self.parameters.lwe_dimension();
        let noise_distribution = self.parameters.lwe_noise_distribution();

        let mut csrng = self.csrng.borrow_mut();

        let a: Vec<R> = standard_distribution
            .sample_iter(&mut *csrng)
            .take(lwe_dimension)
            .collect();
        let b = dot_product(&a, self.lwe_secret_key())
            + encode::<R>(message)
            + noise_distribution.sample(&mut *csrng);

        LWECiphertext::new(a, b)
    }
}

impl<R: RandomRing, F: RandomNTTField> SecretKeyPack<R, F> {
    /// Creates a new [`SecretKeyPack<R, F>`].
    pub fn new(parameters: Parameters<R, F>) -> Self {
        let mut csrng = ChaCha12Rng::from_entropy();

        let lwe_dimension = parameters.lwe_dimension();
        let lwe_secret_key = match parameters.secret_key_type() {
            SecretKeyType::Binary => R::binary_distribution()
                .sample_iter(&mut csrng)
                .take(lwe_dimension)
                .collect(),
            SecretKeyType::Ternary => R::ternary_distribution()
                .sample_iter(&mut csrng)
                .take(lwe_dimension)
                .collect(),
        };

        let rlwe_dimension = parameters.rlwe_dimension();
        let rlwe_secret_key = Polynomial::random(rlwe_dimension, &mut csrng);
        let ntt_rlwe_secret_key = rlwe_secret_key.clone().into_ntt_polynomial();

        Self {
            lwe_secret_key,
            rlwe_secret_key,
            ntt_rlwe_secret_key,
            parameters,
            csrng: RefCell::new(csrng),
        }
    }
}

/// Encodes a message
#[inline]
fn encode<R: Ring>(message: LWEPlaintext) -> R {
    if message {
        R::from(R::modulus_value().rounded_div(R::FOUR_INNER))
    } else {
        R::ZERO
    }
}

/// Decodes a cipher text
fn decode<R: Ring>(encoded_message: R) -> bool {
    let decoded = encoded_message
        .inner()
        .checked_mul(&R::FOUR_INNER)
        .unwrap()
        .rounded_div(R::modulus_value());

    if decoded == R::FOUR_INNER || decoded.is_zero() {
        false
    } else if decoded.is_one() {
        true
    } else {
        panic!("Wrong decoding output: {:?}", decoded);
    }
}

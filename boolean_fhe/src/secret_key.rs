use std::cell::RefCell;

use algebra::{
    reduce::{AddReduce, SubReduce},
    NTTField, NTTPolynomial, Polynomial, RandomNTTField,
};
use rand::prelude::*;
use rand_chacha::ChaCha12Rng;
use rand_distr::Uniform;

use crate::{
    dot_product, LWECiphertext, LWEPlaintext, LWEType, LWEValueBinary, LWEValueTernary, Parameters,
};

/// The distribution type of the LWE Secret Key
#[derive(Debug, Default, Clone, Copy)]
pub enum SecretKeyType {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    #[default]
    Ternary,
}

/// LWE Secret key
pub type LWESecretKey = Vec<LWEType>;

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
pub struct SecretKeyPack<F: NTTField> {
    /// LWE secret key
    lwe_secret_key: LWESecretKey,
    /// RLWE secret key
    rlwe_secret_key: RLWESecretKey<F>,
    /// ntt version RLWE secret key
    ntt_rlwe_secret_key: NTTRLWESecretKey<F>,
    /// boolean fhe's parameters
    parameters: Parameters<F>,
    /// cryptographically secure random number generator
    csrng: RefCell<ChaCha12Rng>,
}

impl<F: NTTField> SecretKeyPack<F> {
    /// Returns the lwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[LWEType] {
        &self.lwe_secret_key
    }

    /// Returns the rlwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn rlwe_secret_key(&self) -> &RLWESecretKey<F> {
        &self.rlwe_secret_key
    }

    /// Returns the ntt rlwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ntt_rlwe_secret_key(&self) -> &NTTRLWESecretKey<F> {
        &self.ntt_rlwe_secret_key
    }

    /// Returns the parameters of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<F> {
        &self.parameters
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt(&self, cipher_text: &LWECiphertext) -> bool {
        let lwe_modulus = self.parameters().lwe_modulus();
        let encoded_message = cipher_text.b().sub_reduce(
            dot_product(cipher_text.a(), self.lwe_secret_key(), lwe_modulus),
            lwe_modulus,
        );
        decode(encoded_message, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEType) {
        let lwe_modulus = self.parameters().lwe_modulus();
        let encoded_message = cipher_text.b().sub_reduce(
            dot_product(cipher_text.a(), self.lwe_secret_key(), lwe_modulus),
            lwe_modulus,
        );
        let message = decode(encoded_message, lwe_modulus.value());

        let fresh = encode(message, lwe_modulus.value());

        (
            message,
            encoded_message
                .sub_reduce(fresh, lwe_modulus)
                .min(fresh.sub_reduce(encoded_message, lwe_modulus)),
        )
    }

    /// Returns the csrng of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn csrng(&self) -> std::cell::Ref<'_, ChaCha12Rng> {
        self.csrng.borrow()
    }

    /// Returns the csrng of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn csrng_mut(&self) -> std::cell::RefMut<'_, ChaCha12Rng> {
        self.csrng.borrow_mut()
    }
}

impl<F: NTTField> SecretKeyPack<F> {
    /// Encrypts [`LWEPlaintext`] into [`LWECiphertext<R>`].
    #[inline]
    pub fn encrypt(&self, message: LWEPlaintext) -> LWECiphertext {
        let lwe_dimension = self.parameters.lwe_dimension();
        let lwe_modulus = self.parameters().lwe_modulus();
        let standard_distribution = Uniform::new_inclusive(0, lwe_modulus.mask());
        let noise_distribution = self.parameters.lwe_noise_distribution();

        let mut csrng = self.csrng_mut();

        let a: Vec<LWEType> = standard_distribution
            .sample_iter(&mut *csrng)
            .take(lwe_dimension)
            .collect();
        let b = dot_product(&a, self.lwe_secret_key(), lwe_modulus)
            .add_reduce(encode(message, lwe_modulus.value()), lwe_modulus)
            .add_reduce(noise_distribution.sample(&mut *csrng), lwe_modulus);

        LWECiphertext::new(a, b)
    }
}

impl<F: RandomNTTField> SecretKeyPack<F> {
    /// Creates a new [`SecretKeyPack<F>`].
    pub fn new(parameters: Parameters<F>) -> Self {
        let mut csrng = ChaCha12Rng::from_entropy();

        let lwe_dimension = parameters.lwe_dimension();
        let lwe_secret_key = match parameters.secret_key_type() {
            SecretKeyType::Binary => LWEValueBinary::new()
                .sample_iter(&mut csrng)
                .take(lwe_dimension)
                .collect(),
            SecretKeyType::Ternary => LWEValueTernary::new(parameters.lwe_modulus().value())
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
fn encode(message: LWEPlaintext, lwe_modulus: LWEType) -> LWEType {
    if message {
        lwe_modulus >> 2
    } else {
        0
    }
}

/// Decodes a cipher text
fn decode(encoded_message: LWEType, lwe_modulus: LWEType) -> bool {
    assert!(lwe_modulus.is_power_of_two() && lwe_modulus >= 8);

    let temp = encoded_message >> (lwe_modulus.trailing_zeros() - 3);
    let decoded = ((temp >> 1) + (temp & 1)) & 3;

    match decoded {
        0 => false,
        1 => true,
        _ => panic!("Wrong decoding output: {:?}", decoded),
    }
}

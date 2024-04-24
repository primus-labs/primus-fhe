use std::cell::RefCell;

use algebra::{
    reduce::{AddReduceAssign, DotProductReduce, SubReduce},
    NTTField, NTTPolynomial, Polynomial,
};
use lattice::{sample_binary_values, sample_ternary_values};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use crate::{decode, encode, LWECiphertext, LWEPlaintext, LWEMessage, Parameters};

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
pub type LWESecretKey = Vec<LWEPlaintext>;

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
    /// Creates a new [`SecretKeyPack<F>`].
    pub fn new(parameters: Parameters<F>) -> Self {
        let mut csrng = ChaCha12Rng::from_entropy();

        let lwe_dimension = parameters.lwe_dimension();

        let lwe_secret_key = match parameters.secret_key_type() {
            SecretKeyType::Binary => sample_binary_values(lwe_dimension, &mut csrng),
            SecretKeyType::Ternary => {
                sample_ternary_values(parameters.lwe_modulus().value(), lwe_dimension, &mut csrng)
            }
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

    /// Returns the lwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[LWEPlaintext] {
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

    /// Encrypts [`LWEPlaintext`] into [`LWECiphertext<R>`].
    #[inline]
    pub fn encrypt(&self, message: LWEMessage) -> LWECiphertext {
        let lwe_modulus = self.parameters().lwe_modulus();
        let noise_distribution = self.parameters.lwe_noise_distribution();
        let mut csrng = self.csrng_mut();

        let mut cipher = LWECiphertext::generate_random_zero_sample(
            self.lwe_secret_key(),
            lwe_modulus.value(),
            lwe_modulus,
            noise_distribution,
            &mut *csrng,
        );

        cipher
            .b_mut()
            .add_reduce_assign(encode(message, lwe_modulus.value()), lwe_modulus);

        cipher
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt(&self, cipher_text: &LWECiphertext) -> bool {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEPlaintext::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);
        let encoded_message = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(encoded_message, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEPlaintext) {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEPlaintext::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);

        let encoded_message = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);
        let message = decode(encoded_message, lwe_modulus.value());

        let fresh = encode(message, lwe_modulus.value());

        (
            message,
            encoded_message
                .sub_reduce(fresh, lwe_modulus)
                .min(fresh.sub_reduce(encoded_message, lwe_modulus)),
        )
    }
}

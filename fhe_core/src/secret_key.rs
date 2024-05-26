use std::cell::RefCell;

use algebra::{
    reduce::{AddReduceAssign, DotProductReduce, SubReduce},
    NTTField, NTTPolynomial, Polynomial,
};
use lattice::{sample_binary_values, sample_ternary_values};
use num_traits::Inv;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use crate::{decode, encode, LWEBoolMessage, LWECiphertext, LWEModulusType, Parameters};

/// The distribution type of the LWE Secret Key
#[derive(Debug, Default, Clone, Copy)]
pub enum SecretKeyType {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    #[default]
    Ternary,
}

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// RLWE secret key, ntt version RLWE secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<F: NTTField> {
    /// LWE secret key
    lwe_secret_key: Vec<LWEModulusType>,
    /// RLWE secret key
    rlwe_secret_key: Polynomial<F>,
    /// ntt version RLWE secret key
    ntt_rlwe_secret_key: NTTPolynomial<F>,
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

        let rlwe_dimension = parameters.ring_dimension();
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
    pub fn lwe_secret_key(&self) -> &[LWEModulusType] {
        &self.lwe_secret_key
    }

    /// Returns the rlwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn rlwe_secret_key(&self) -> &Polynomial<F> {
        &self.rlwe_secret_key
    }

    /// Returns the ntt rlwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ntt_rlwe_secret_key(&self) -> &NTTPolynomial<F> {
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
    pub fn encrypt(&self, message: LWEBoolMessage) -> LWECiphertext {
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
            LWEModulusType::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);
        let encoded_message = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(encoded_message, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEModulusType) {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEModulusType::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);

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

/// NTRU Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct NTRUSecretKeyPack<F: NTTField> {
    /// LWE secret key
    lwe_secret_key: Vec<LWEModulusType>,
    /// ring secret key
    ring_secret_key: Polynomial<F>,
    /// ntt version ring secret key
    ntt_ring_secret_key: NTTPolynomial<F>,
    /// ntt version inverse ring secret key
    ntt_inv_ring_secret_key: NTTPolynomial<F>,
    /// boolean fhe's parameters
    parameters: Parameters<F>,
    /// cryptographically secure random number generator
    csrng: RefCell<ChaCha12Rng>,
}

impl<F: NTTField> NTRUSecretKeyPack<F> {
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

        let four = F::ONE + F::ONE + F::ONE + F::ONE;
        let ntru_dimension = parameters.ring_dimension();
        let chi = parameters.ring_noise_distribution();
        let mut ring_secret_key = Polynomial::random_with_gaussian(ntru_dimension, &mut csrng, chi);
        ring_secret_key.mul_scalar_assign(four);
        ring_secret_key[0] += F::ONE;
        let ntt_ring_secret_key = ring_secret_key.clone().into_ntt_polynomial();
        let ntt_inv_ring_secret_key = (&ntt_ring_secret_key).inv();

        Self {
            lwe_secret_key,
            ring_secret_key,
            ntt_ring_secret_key,
            ntt_inv_ring_secret_key,
            parameters,
            csrng: RefCell::new(csrng),
        }
    }

    /// Returns the lwe secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[LWEModulusType] {
        &self.lwe_secret_key
    }

    /// Returns the ring secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ring_secret_key(&self) -> &Polynomial<F> {
        &self.ring_secret_key
    }

    /// Returns the ntt ring secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ntt_ring_secret_key(&self) -> &NTTPolynomial<F> {
        &self.ntt_ring_secret_key
    }

    /// Returns a reference to the ntt inv ring secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ntt_inv_ring_secret_key(&self) -> &NTTPolynomial<F> {
        self.ntt_inv_ring_secret_key.as_ref()
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

    /// Encrypts [`LWEMessage`] into [`LWECiphertext<R>`].
    #[inline]
    pub fn encrypt(&self, message: LWEBoolMessage) -> LWECiphertext {
        let lwe_modulus = self.parameters.lwe_modulus();
        let noise_distribution = self.parameters.lwe_noise_distribution();
        let lwe_modulus_value = lwe_modulus.value();
        let mut csrng = self.csrng_mut();

        let mut cipher = LWECiphertext::generate_random_zero_sample(
            self.lwe_secret_key(),
            lwe_modulus_value,
            lwe_modulus,
            noise_distribution,
            &mut *csrng,
        );

        cipher
            .b_mut()
            .add_reduce_assign(encode(message, lwe_modulus_value), lwe_modulus);

        cipher
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEMessage`]
    #[inline]
    pub fn decrypt(&self, cipher_text: &LWECiphertext) -> bool {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEModulusType::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);
        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(plaintext, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEMessage`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEModulusType) {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEModulusType::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);

        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);
        let message = decode(plaintext, lwe_modulus.value());

        let fresh = encode(message, lwe_modulus.value());

        (
            message,
            plaintext
                .sub_reduce(fresh, lwe_modulus)
                .min(fresh.sub_reduce(plaintext, lwe_modulus)),
        )
    }
}

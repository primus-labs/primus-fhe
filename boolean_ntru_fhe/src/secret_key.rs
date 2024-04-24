use std::cell::RefCell;

use algebra::{
    reduce::{AddReduceAssign, DotProductReduce, SubReduce},
    NTTField, NTTPolynomial, Polynomial,
};
use lattice::{sample_binary_values, sample_ternary_values};
use num_traits::Inv;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use crate::{decode, encode, LWECiphertext, LWEMessage, LWEPlaintext, Parameters};

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

/// Ring Secret key
pub type RingSecretKey<F> = Polynomial<F>;

/// NTT version Ring Secret key
pub type NTTRingSecretKey<F> = NTTPolynomial<F>;

/// NTT version Ring Secret key
pub type NTTInvRingSecretKey<F> = NTTPolynomial<F>;

/// Boolean fhe's secret keys pack.
///
/// This struct contains the LWE secret key,
/// ring secret key, ntt version ring secret key
/// and boolean fhe's parameters.
#[derive(Clone)]
pub struct SecretKeyPack<F: NTTField> {
    /// LWE secret key
    lwe_secret_key: LWESecretKey,
    /// ring secret key
    ring_secret_key: RingSecretKey<F>,
    /// ntt version ring secret key
    ntt_ring_secret_key: NTTRingSecretKey<F>,
    /// ntt version inverse ring secret key
    ntt_inv_ring_secret_key: NTTInvRingSecretKey<F>,
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

        let ntru_dimension = parameters.ntru_dimension();
        let ring_secret_key = Polynomial::random(ntru_dimension, &mut csrng);
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
    pub fn lwe_secret_key(&self) -> &[LWEPlaintext] {
        &self.lwe_secret_key
    }

    /// Returns the ring secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ring_secret_key(&self) -> &RingSecretKey<F> {
        &self.ring_secret_key
    }

    /// Returns the ntt ring secret key of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn ntt_ring_secret_key(&self) -> &NTTRingSecretKey<F> {
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
        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(plaintext, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEPlaintext) {
        let lwe_modulus = self.parameters().lwe_modulus();

        let a_mul_s =
            LWEPlaintext::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);

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

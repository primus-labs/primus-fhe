use std::cell::RefCell;

use algebra::{
    reduce::{AddReduceAssign, DotProductReduce, SubReduce},
    utils::Prg,
    NTTField, NTTPolynomial, Polynomial,
};
use lattice::{sample_binary_values, sample_ternary_values};
use num_traits::Inv;

use crate::{
    ciphertext::LWECiphertext, decode, encode, BlindRotationType, LWEBoolMessage, LWEModulusType,
    Parameters, StepsAfterBR,
};

/// The distribution type of the LWE Secret Key
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum SecretKeyType {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    #[default]
    Ternary,
}

/// The distribution type of the Ring Secret Key
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum RingSecretKeyType {
    /// Binary SecretKey Distribution
    Binary,
    /// Ternary SecretKey Distribution
    #[default]
    Ternary,
    /// Gaussian SecretKey Distribution
    Gaussian,
    /// Uniform SecretKey Distribution
    Uniform,
}

/// LWE Secret key
pub type LWESecretKey = Vec<LWEModulusType>;

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
pub struct SecretKeyPack<F: NTTField> {
    /// LWE secret key
    lwe_secret_key: LWESecretKey,
    /// ring secret key
    ring_secret_key: RingSecretKey<F>,
    /// ntt version ring secret key
    ntt_ring_secret_key: NTTRingSecretKey<F>,
    /// ntt version inverse ring secret key
    ntt_inv_ring_secret_key: Option<NTTRingSecretKey<F>>,
    /// boolean fhe's parameters
    parameters: Parameters<F>,
    /// cryptographically secure random number generator
    csrng: RefCell<Prg>,
}

impl<F: NTTField> SecretKeyPack<F> {
    fn create_lwe_secret_key(parameters: &Parameters<F>, csrng: &mut Prg) -> Vec<LWEModulusType> {
        let lwe_dimension = parameters.lwe_dimension();

        match parameters.secret_key_type() {
            SecretKeyType::Binary => sample_binary_values(lwe_dimension, csrng),
            SecretKeyType::Ternary => {
                sample_ternary_values(parameters.lwe_modulus().value(), lwe_dimension, csrng)
            }
        }
    }

    /// Creates a new [`SecretKeyPack<F>`].
    pub fn new(parameters: Parameters<F>) -> Self {
        let mut csrng = Prg::new();

        let lwe_secret_key = Self::create_lwe_secret_key(&parameters, &mut csrng);

        let ring_dimension = parameters.ring_dimension();

        let ring_secret_key;
        let ntt_ring_secret_key;
        let ntt_inv_ring_secret_key;

        match parameters.blind_rotation_type() {
            BlindRotationType::RLWE => {
                ring_secret_key = match parameters.steps_after_blind_rotation() {
                    StepsAfterBR::KsMs => Polynomial::random(ring_dimension, &mut csrng),
                    StepsAfterBR::Ms => {
                        assert!(
                            parameters.ring_secret_key_type() == RingSecretKeyType::Binary
                                || parameters.ring_secret_key_type() == RingSecretKeyType::Ternary
                        );
                        // negative convertion
                        let convert = |v: &LWEModulusType| match *v {
                            0 => F::zero(),
                            1 => F::neg_one(),
                            _ => F::one(),
                        };

                        // s = [s_0, -s_{n-1},..., -s_1]
                        let mut s =
                            <Polynomial<F>>::new(lwe_secret_key.iter().map(convert).collect());
                        s[0] = -s[0];
                        s[1..].reverse();

                        s
                    }
                };
                ntt_ring_secret_key = ring_secret_key.clone().into_ntt_polynomial();
                ntt_inv_ring_secret_key = None;
            }
            BlindRotationType::NTRU => {
                let four = F::one() + F::one() + F::one() + F::one();
                let chi = parameters.ring_noise_distribution();
                ring_secret_key = {
                    let mut ring_secret_key =
                        Polynomial::random_with_gaussian(ring_dimension, &mut csrng, chi);
                    ring_secret_key.mul_scalar_assign(four);
                    ring_secret_key[0] += F::one();
                    ring_secret_key
                };
                ntt_ring_secret_key = ring_secret_key.clone().into_ntt_polynomial();
                ntt_inv_ring_secret_key = Some((&ntt_ring_secret_key).inv());
            }
        }
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
    pub fn ntt_inv_ring_secret_key(&self) -> Option<&NTTPolynomial<F>> {
        self.ntt_inv_ring_secret_key.as_ref()
    }

    /// Returns the parameters of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<F> {
        &self.parameters
    }

    /// Returns the csrng of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn csrng(&self) -> std::cell::Ref<'_, Prg> {
        self.csrng.borrow()
    }

    /// Returns the csrng of this [`SecretKeyPack<F>`].
    #[inline]
    pub fn csrng_mut(&self) -> std::cell::RefMut<'_, Prg> {
        self.csrng.borrow_mut()
    }

    /// Encrypts [`LWEModulusType`] into [`LWECiphertext`].
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

    /// Decrypts the [`LWECiphertext`] back to [`LWEBoolMessage`]
    #[inline]
    pub fn decrypt(&self, cipher_text: &LWECiphertext) -> bool {
        let lwe_modulus = self.parameters.lwe_modulus();

        let a_mul_s =
            LWEModulusType::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);
        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(plaintext, lwe_modulus.value())
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEBoolMessage`]
    #[inline]
    pub fn decrypt_with_noise(&self, cipher_text: &LWECiphertext) -> (bool, LWEModulusType) {
        let lwe_modulus = self.parameters.lwe_modulus();

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

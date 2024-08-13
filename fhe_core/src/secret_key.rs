use std::cell::RefCell;

use algebra::{utils::Prg, NTTField, NTTPolynomial, Polynomial};
use lattice::{sample_binary_values, sample_ternary_values};
use num_traits::Inv;

use crate::{
    ciphertext::LWECiphertext, decode, encode, parameter::LWEParameters, BlindRotationType,
    LWEModulusType, LWEMsgType, Parameters, StepsAfterBR,
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
    /// Uniform SecretKey Distribution.
    Uniform,
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
pub struct SecretKeyPack<C: LWEModulusType, Q: NTTField, Qks: NTTField> {
    /// LWE secret key
    lwe_secret_key: Vec<C>,

    /// ring secret key
    ring_secret_key: RingSecretKey<Q>,
    /// ntt version ring secret key
    ntt_ring_secret_key: NTTRingSecretKey<Q>,
    /// ntt version inverse ring secret key
    ntt_inv_ring_secret_key: Option<NTTRingSecretKey<Q>>,

    /// boolean fhe's parameters
    parameters: Parameters<C, Q, Qks>,

    /// cryptographically secure random number generator
    csrng: RefCell<Prg>,
}

impl<C: LWEModulusType, Q: NTTField, Qks: NTTField> SecretKeyPack<C, Q, Qks> {
    fn create_lwe_secret_key(params: &LWEParameters<C>, csrng: &mut Prg) -> Vec<C> {
        match params.secret_key_type {
            LWESecretKeyType::Binary => sample_binary_values(params.dimension, csrng),
            LWESecretKeyType::Ternary => {
                sample_ternary_values(params.cipher_modulus_value, params.dimension, csrng)
            }
        }
    }

    /// Creates a new [`SecretKeyPack<C, Q, Qks>`].
    pub fn new(params: Parameters<C, Q, Qks>) -> Self {
        let mut csrng = Prg::new();

        let lwe_secret_key = Self::create_lwe_secret_key(&params.lwe_params(), &mut csrng);

        let ring_dimension = params.ring_dimension();

        let ring_secret_key;
        let ntt_ring_secret_key;
        let ntt_inv_ring_secret_key;

        match params.blind_rotation_type() {
            BlindRotationType::RLWE => {
                ring_secret_key = match params.steps_after_blind_rotation() {
                    StepsAfterBR::MsKsMs => match params.ring_secret_key_type() {
                        RingSecretKeyType::Binary => {
                            Polynomial::random_with_binary(ring_dimension, &mut csrng)
                        }
                        RingSecretKeyType::Ternary => {
                            Polynomial::random_with_ternary(ring_dimension, &mut csrng)
                        }
                        RingSecretKeyType::Gaussian => unimplemented!(),
                        RingSecretKeyType::Uniform => panic!(),
                    },
                    StepsAfterBR::KsMs => match params.ring_secret_key_type() {
                        RingSecretKeyType::Binary => {
                            Polynomial::random_with_binary(ring_dimension, &mut csrng)
                        }
                        RingSecretKeyType::Ternary => {
                            Polynomial::random_with_ternary(ring_dimension, &mut csrng)
                        }
                        RingSecretKeyType::Gaussian => Polynomial::random_with_gaussian(
                            ring_dimension,
                            &mut csrng,
                            params.ring_noise_distribution(),
                        ),
                        RingSecretKeyType::Uniform => {
                            Polynomial::random(ring_dimension, &mut csrng)
                        }
                    },
                    StepsAfterBR::Ms => {
                        assert!(
                            params.ring_secret_key_type() == RingSecretKeyType::Binary
                                || params.ring_secret_key_type() == RingSecretKeyType::Ternary
                        );
                        assert_eq!(params.lwe_dimension(), params.ring_dimension());
                        // convertion
                        let convert = |v: &C| {
                            if *v == C::ZERO {
                                Q::zero()
                            } else if *v == C::ONE {
                                Q::one()
                            } else {
                                Q::neg_one()
                            }
                        };

                        // s = [s_0, s_1,..., s_{n-1}]
                        <Polynomial<Q>>::new(lwe_secret_key.iter().map(convert).collect())
                    }
                };
                ntt_ring_secret_key = ring_secret_key.clone().into_ntt_polynomial();
                ntt_inv_ring_secret_key = None;
            }
            BlindRotationType::NTRU => {
                let four = Q::one() + Q::one() + Q::one() + Q::one();
                let chi = params.ring_noise_distribution();
                ring_secret_key = {
                    let mut ring_secret_key =
                        Polynomial::random_with_gaussian(ring_dimension, &mut csrng, chi);
                    ring_secret_key.mul_scalar_assign(four);
                    ring_secret_key[0] += Q::one();
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
            parameters: params,
            csrng: RefCell::new(csrng),
        }
    }

    /// Returns the lwe secret key of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn lwe_secret_key(&self) -> &[C] {
        &self.lwe_secret_key
    }

    /// Returns the ring secret key of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn ring_secret_key(&self) -> &RingSecretKey<Q> {
        &self.ring_secret_key
    }

    /// Returns the ntt ring secret key of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn ntt_ring_secret_key(&self) -> &NTTRingSecretKey<Q> {
        &self.ntt_ring_secret_key
    }

    /// Returns a reference to the ntt inv ring secret key of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn ntt_inv_ring_secret_key(&self) -> Option<&NTTPolynomial<Q>> {
        self.ntt_inv_ring_secret_key.as_ref()
    }

    /// Returns the parameters of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<C, Q, Qks> {
        &self.parameters
    }

    /// Returns the csrng of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn csrng(&self) -> std::cell::Ref<'_, Prg> {
        self.csrng.borrow()
    }

    /// Returns the csrng of this [`SecretKeyPack<C, Q, Qks>`].
    #[inline]
    pub fn csrng_mut(&self) -> std::cell::RefMut<'_, Prg> {
        self.csrng.borrow_mut()
    }

    /// Encrypts message into [`LWECiphertext`].
    #[inline]
    pub fn encrypt<M: LWEMsgType>(&self, message: M) -> LWECiphertext<C> {
        let lwe_modulus = self.parameters.lwe_cipher_modulus();
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

        cipher.b_mut().add_reduce_assign(
            encode(
                message,
                self.parameters.lwe_plain_modulus(),
                lwe_modulus_value.as_into(),
            ),
            lwe_modulus,
        );

        cipher
    }

    /// Decrypts the [`LWECiphertext`] back to message
    #[inline]
    pub fn decrypt<M: LWEMsgType>(&self, cipher_text: &LWECiphertext<C>) -> M {
        let lwe_modulus = self.parameters.lwe_cipher_modulus();

        let a_mul_s = C::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);
        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        decode(
            plaintext,
            self.parameters.lwe_plain_modulus(),
            lwe_modulus.value().as_into(),
        )
    }

    /// Decrypts the [`LWECiphertext`] back to message
    #[inline]
    pub fn decrypt_with_noise<M: LWEMsgType>(&self, cipher_text: &LWECiphertext<C>) -> (M, C) {
        let lwe_modulus = self.parameters.lwe_cipher_modulus();
        let t: u64 = self.parameters.lwe_plain_modulus();
        let q: u64 = lwe_modulus.value().as_into();

        let a_mul_s = C::dot_product_reduce(cipher_text.a(), self.lwe_secret_key(), lwe_modulus);

        let plaintext = cipher_text.b().sub_reduce(a_mul_s, lwe_modulus);

        let message = decode(plaintext, t, q);

        let fresh = encode(message, t, q);

        (
            message,
            plaintext
                .sub_reduce(fresh, lwe_modulus)
                .min(fresh.sub_reduce(plaintext, lwe_modulus)),
        )
    }
}

use std::ops::Deref;

use algebra::{
    integer::UnsignedInteger,
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::{sample_binary_values, sample_ternary_values, DiscreteGaussian},
    reduce::RingReduce,
    Field, NttField,
};
use num_traits::{ConstOne, ConstZero, One, Zero};
use rand::{CryptoRng, Rng};

use crate::{decode, encode, LweCiphertext, LweParameters};

/// The distribution type of the LWE Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum LweSecretKeyType {
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

#[derive(Clone)]
pub struct LweSecretKey<C: UnsignedInteger> {
    key: Vec<C>,
    distr: LweSecretKeyType,
}

impl<C: UnsignedInteger> AsRef<[C]> for LweSecretKey<C> {
    #[inline]
    fn as_ref(&self) -> &[C] {
        &self.key
    }
}

impl<C: UnsignedInteger> LweSecretKey<C> {
    #[inline]
    pub fn new(key: Vec<C>, distr: LweSecretKeyType) -> Self {
        Self { key, distr }
    }

    #[inline]
    pub fn dimension(&self) -> usize {
        self.key.len()
    }

    #[inline]
    pub fn generate<R>(params: &LweParameters<C>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let distr = params.secret_key_type;
        let key = match distr {
            LweSecretKeyType::Binary => sample_binary_values(params.dimension, rng),
            LweSecretKeyType::Ternary => {
                sample_ternary_values(params.cipher_modulus_minus_one, params.dimension, rng)
            }
        };
        Self { key, distr }
    }

    #[inline]
    pub fn from_rlwe_secret_key<F: NttField>(
        rlwe_secret_key: &RlweSecretKey<F>,
        lwe_cipher_modulus_minus_one: C,
    ) -> Self {
        let distr = match rlwe_secret_key.distr {
            RingSecretKeyType::Binary => LweSecretKeyType::Binary,
            RingSecretKeyType::Ternary => LweSecretKeyType::Ternary,
            RingSecretKeyType::Gaussian => panic!("Not support"),
        };
        let convert = |value: &<F as Field>::ValueT| {
            if value.is_zero() {
                C::ZERO
            } else if value.is_one() {
                C::ONE
            } else {
                lwe_cipher_modulus_minus_one
            }
        };

        Self {
            key: rlwe_secret_key.iter().map(convert).collect(),
            distr,
        }
    }

    #[inline]
    pub fn distr(&self) -> LweSecretKeyType {
        self.distr
    }

    /// Encrypts message into [`LweCiphertext<C>`].
    #[inline]
    pub fn encrypt<M, R>(
        &self,
        message: M,
        params: &LweParameters<C>,
        cipher_modulus: impl RingReduce<C>,
        rng: &mut R,
    ) -> LweCiphertext<C>
    where
        M: TryInto<C>,
        R: Rng + CryptoRng,
    {
        let gaussian = params.noise_distribution();
        let mut ciphertext = LweCiphertext::generate_random_zero_sample(
            self.as_ref(),
            cipher_modulus,
            gaussian,
            rng,
        );
        cipher_modulus.reduce_add_assign(
            ciphertext.b_mut(),
            encode(
                message,
                params.plain_modulus_value,
                params.cipher_modulus_value,
            ),
        );

        ciphertext
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        params: &LweParameters<C>,
        cipher_modulus: impl RingReduce<C>,
    ) -> M
    where
        M: TryFrom<C>,
    {
        let a_mul_s = cipher_modulus.reduce_dot_product(cipher_text.a(), self);
        let plaintext = cipher_modulus.reduce_sub(cipher_text.b(), a_mul_s);

        decode(
            plaintext,
            params.plain_modulus_value,
            params.cipher_modulus_value,
        )
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt_with_noise<M>(
        &self,
        cipher_text: &LweCiphertext<C>,
        params: &LweParameters<C>,
        cipher_modulus: impl RingReduce<C>,
    ) -> (M, C)
    where
        M: Copy + TryFrom<C> + TryInto<C>,
    {
        let a_mul_s = cipher_modulus.reduce_dot_product(cipher_text.a(), self);
        let plaintext = cipher_modulus.reduce_sub(cipher_text.b(), a_mul_s);

        let t = params.plain_modulus_value;
        let q = params.cipher_modulus_value;
        let message = decode(plaintext, t, q);
        let fresh = encode(message, t, q);

        (
            message,
            cipher_modulus
                .reduce_sub(plaintext, fresh)
                .min(cipher_modulus.reduce_sub(fresh, plaintext)),
        )
    }
}

/// Rlwe Secret key
#[derive(Clone)]
pub struct RlweSecretKey<F: NttField> {
    key: FieldPolynomial<F>,
    distr: RingSecretKeyType,
}

impl<F: NttField> Deref for RlweSecretKey<F> {
    type Target = FieldPolynomial<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<F: NttField> RlweSecretKey<F> {
    #[inline]
    pub fn new(key: FieldPolynomial<F>, distr: RingSecretKeyType) -> Self {
        Self { key, distr }
    }

    #[inline]
    pub fn generate<R: Rng + CryptoRng>(
        secret_key_type: RingSecretKeyType,
        dimension: usize,
        gaussian: Option<DiscreteGaussian<<F as Field>::ValueT>>,
        rng: &mut R,
    ) -> Self {
        let distr = secret_key_type;
        let key = match distr {
            RingSecretKeyType::Binary => FieldPolynomial::random_binary(dimension, rng),
            RingSecretKeyType::Ternary => FieldPolynomial::random_ternary(dimension, rng),
            RingSecretKeyType::Gaussian => {
                FieldPolynomial::random_gaussian(dimension, gaussian.unwrap(), rng)
            }
        };

        Self { key, distr }
    }

    #[inline]
    pub fn from_lwe_secret_key<C: UnsignedInteger>(lwe_secret_key: &LweSecretKey<C>) -> Self {
        let convert = |v: &C| {
            if v.is_zero() {
                <<F as Field>::ValueT as ConstZero>::ZERO
            } else if v.is_one() {
                <<F as Field>::ValueT as ConstOne>::ONE
            } else {
                <F as Field>::MINUS_ONE
            }
        };
        let distr = match lwe_secret_key.distr {
            LweSecretKeyType::Binary => RingSecretKeyType::Binary,
            LweSecretKeyType::Ternary => RingSecretKeyType::Ternary,
        };

        RlweSecretKey {
            key: FieldPolynomial::new(lwe_secret_key.as_ref().iter().map(convert).collect()),
            distr,
        }
    }

    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }
}

/// NTT version Ring Secret key
#[derive(Clone)]
pub struct NttRlweSecretKey<F: NttField> {
    key: FieldNttPolynomial<F>,
    distr: RingSecretKeyType,
}

impl<F: NttField> Deref for NttRlweSecretKey<F> {
    type Target = FieldNttPolynomial<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<F: NttField> NttRlweSecretKey<F> {
    #[inline]
    pub fn from_coeff_secret_key(
        secret_key: &RlweSecretKey<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Self {
        Self {
            key: ntt_table.transform(&secret_key.key),
            distr: secret_key.distr,
        }
    }

    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }
}

use std::ops::Deref;

use algebra::{
    integer::UnsignedInteger,
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial, Polynomial},
    random::{sample_binary_values, sample_ternary_values, DiscreteGaussian},
    reduce::{ModulusValue, RingReduce},
    utils::Size,
    Field, NttField,
};
use lattice::{NumRlwe, SparseRlwe};
use num_traits::{ConstOne, ConstZero, One, Zero};
use rand::{distributions::Uniform, prelude::Distribution, CryptoRng, Rng};

use crate::{
    decode, encode, CmLweCiphertext, LweCiphertext, LweParameters, NttRlweCiphertext,
    RlweParameters,
};

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

/// Represents a secret key for the Learning with Errors (LWE) cryptographic scheme.
///
/// # Type Parameters
///
/// * `C` - An unsigned integer type that represents the coefficients of the secret key.
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
    /// Creates a new `LweSecretKey` with the specified key and distribution type.
    ///
    /// # Arguments
    ///
    /// * `key` - A vector containing the secret key coefficients.
    /// * `distr` - The distribution type of the secret key.
    ///
    /// # Returns
    ///
    /// A new instance of `LweSecretKey`.
    #[inline]
    pub fn new(key: Vec<C>, distr: LweSecretKeyType) -> Self {
        Self { key, distr }
    }

    /// Returns the dimension of the secret key.
    ///
    /// # Returns
    ///
    /// The dimension of the secret key.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.key.len()
    }

    /// Generates a new `LweSecretKey` with random coefficients.
    ///
    /// # Arguments
    ///
    /// * `params` - The parameters for the LWE scheme.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `LweSecretKey` with random coefficients.
    #[inline]
    pub fn generate<R, M>(params: &LweParameters<C, M>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
        M: RingReduce<C>,
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

    /// Creates a new `LweSecretKey` from an RLWE secret key.
    ///
    /// # Arguments
    ///
    /// * `rlwe_secret_key` - A reference to the RLWE secret key.
    /// * `lwe_cipher_modulus_minus_one` - The modulus minus one for the LWE scheme.
    ///
    /// # Returns
    ///
    /// A new instance of `LweSecretKey` created from the RLWE secret key.
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

    /// Returns the distr of this [`LweSecretKey<C>`].
    #[inline]
    pub fn distr(&self) -> LweSecretKeyType {
        self.distr
    }

    /// Encrypts message into [`LweCiphertext<C>`].
    #[inline]
    pub fn encrypt<Msg, R, Modulus>(
        &self,
        message: Msg,
        params: &LweParameters<C, Modulus>,
        rng: &mut R,
    ) -> LweCiphertext<C>
    where
        Msg: TryInto<C>,
        R: Rng + CryptoRng,
        Modulus: RingReduce<C>,
    {
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let mut ciphertext =
            LweCiphertext::generate_random_zero_sample(self.as_ref(), modulus, &gaussian, rng);
        modulus.reduce_add_assign(
            ciphertext.b_mut(),
            encode(
                message,
                params.plain_modulus_value,
                params.cipher_modulus_value,
            ),
        );

        ciphertext
    }

    /// Encrypts multiple messages using the secret key.
    ///
    /// # Arguments
    ///
    /// * `messages` - A slice of messages to be encrypted.
    /// * `params` - The parameters for the LWE scheme.
    /// * `csrng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A `CmLweCiphertext` containing the encrypted messages.
    #[inline]
    pub fn encrypt_multi_messages<Msg, R, Modulus>(
        &self,
        messages: &[Msg],
        params: &LweParameters<C, Modulus>,
        csrng: &mut R,
    ) -> CmLweCiphertext<C>
    where
        Msg: Copy + TryInto<C>,
        R: Rng + CryptoRng,
        Modulus: RingReduce<C>,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let distr = <Uniform<C>>::new_inclusive(C::ZERO, params.cipher_modulus_minus_one());

        let mut a = Polynomial::zero(dimension);
        let mut b = Polynomial::zero(dimension);

        for (i, o) in a.iter_mut().zip(distr.sample_iter(&mut *csrng)) {
            *i = o;
        }

        a.naive_mul_inplace(&self.key, modulus, &mut b);

        for (&message, bi) in messages.iter().zip(b.iter_mut()) {
            modulus.reduce_add_assign(
                bi,
                encode(
                    message,
                    params.plain_modulus_value,
                    params.cipher_modulus_value,
                ),
            );
        }

        for (bi, ei) in b.iter_mut().zip(gaussian.sample_iter(&mut *csrng)) {
            modulus.reduce_add_assign(bi, ei);
        }

        NumRlwe::new(a, b).extract_first_few_lwe_locally(messages.len(), modulus)
    }

    /// Encrypts multiple zeros using the secret key.
    ///
    /// # Arguments
    ///
    /// * `zero_count` - The count of zeros to be encrypted.
    /// * `params` - The parameters for the LWE scheme.
    /// * `csrng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A `CmLweCiphertext` containing the encrypted messages.
    #[inline]
    pub fn encrypt_multi_zeros<R, Modulus>(
        &self,
        zero_count: usize,
        params: &LweParameters<C, Modulus>,
        csrng: &mut R,
    ) -> CmLweCiphertext<C>
    where
        R: Rng + CryptoRng,
        Modulus: RingReduce<C>,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let distr = <Uniform<C>>::new_inclusive(C::ZERO, params.cipher_modulus_minus_one());

        let mut a = Polynomial::zero(dimension);
        let mut b = Polynomial::zero(dimension);

        a.iter_mut()
            .zip(distr.sample_iter(&mut *csrng))
            .for_each(|(i, o): (&mut C, C)| {
                *i = o;
            });

        a.naive_mul_inplace(&self.key, modulus, &mut b);

        for (bi, ei) in b.iter_mut().zip(gaussian.sample_iter(&mut *csrng)) {
            modulus.reduce_add_assign(bi, ei);
        }

        NumRlwe::new(a, b).extract_first_few_lwe_locally(zero_count, modulus)
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt<Msg, Modulus>(
        &self,
        cipher_text: &LweCiphertext<C>,
        params: &LweParameters<C, Modulus>,
    ) -> Msg
    where
        Msg: TryFrom<C>,
        Modulus: RingReduce<C>,
    {
        let modulus = params.cipher_modulus;

        let a_mul_s = modulus.reduce_dot_product(cipher_text.a(), self);
        let plaintext = modulus.reduce_sub(cipher_text.b(), a_mul_s);

        decode(
            plaintext,
            params.plain_modulus_value,
            params.cipher_modulus_value,
        )
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt_with_noise<Msg, Modulus>(
        &self,
        cipher_text: &LweCiphertext<C>,
        params: &LweParameters<C, Modulus>,
    ) -> (Msg, C)
    where
        Msg: Copy + TryFrom<C> + TryInto<C>,
        Modulus: RingReduce<C>,
    {
        let modulus = params.cipher_modulus;
        let a_mul_s = modulus.reduce_dot_product(cipher_text.a(), self);
        let plaintext = modulus.reduce_sub(cipher_text.b(), a_mul_s);

        let t = params.plain_modulus_value;
        let q = params.cipher_modulus_value;
        let message = decode(plaintext, t, q);
        let fresh = encode(message, t, q);

        (
            message,
            modulus
                .reduce_sub(plaintext, fresh)
                .min(modulus.reduce_sub(fresh, plaintext)),
        )
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt_multi_messages<Msg, Modulus>(
        &self,
        cipher_text: &CmLweCiphertext<C>,
        params: &LweParameters<C, Modulus>,
    ) -> Vec<Msg>
    where
        Msg: TryFrom<C>,
        Modulus: RingReduce<C>,
    {
        let modulus = params.cipher_modulus;
        let dimension = cipher_text.a().len();

        cipher_text
            .b()
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let a_mul_s = modulus.reduce_dot_product2(
                    cipher_text.a()[dimension - i..]
                        .iter()
                        .map(|&v| modulus.reduce_neg(v))
                        .chain(cipher_text.a()[..dimension - i].iter().copied()),
                    self.key.iter().copied(),
                );
                let plaintext = modulus.reduce_sub(b, a_mul_s);

                decode(
                    plaintext,
                    params.plain_modulus_value,
                    params.cipher_modulus_value,
                )
            })
            .collect()
    }
}

impl<C: UnsignedInteger> Size for LweSecretKey<C> {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}

/// Represents a secret key for the Ring Learning with Errors (RLWE) cryptographic scheme.
///
/// # Type Parameters
///
/// * `F` - A field that supports Number Theoretic Transform (NTT) operations.
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
    /// Creates a new `RlweSecretKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - A polynomial representing the secret key.
    /// * `distr` - The distribution type of the secret key.
    ///
    /// # Returns
    ///
    /// A new instance of `RlweSecretKey`.
    #[inline]
    pub fn new(key: FieldPolynomial<F>, distr: RingSecretKeyType) -> Self {
        Self { key, distr }
    }

    /// Generates a new `RlweSecretKey` with random coefficients.
    ///
    /// # Arguments
    ///
    /// * `secret_key_type` - The distribution type of the secret key.
    /// * `dimension` - The dimension of the secret key.
    /// * `gaussian` - An optional Gaussian distribution for generating random samples.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `RlweSecretKey` with random coefficients.
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
                FieldPolynomial::random_gaussian(dimension, &gaussian.unwrap(), rng)
            }
        };

        Self { key, distr }
    }

    /// Creates a new `RlweSecretKey` from an LWE secret key.
    ///
    /// # Arguments
    ///
    /// * `lwe_secret_key` - A reference to the LWE secret key.
    ///
    /// # Returns
    ///
    /// A new instance of `RlweSecretKey` created from the LWE secret key.
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

    /// Returns the distribution type of the secret key.
    ///
    /// # Returns
    ///
    /// The distribution type of the secret key.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }
}

/// Represents a secret key for the Number Theoretic Transform (NTT) Ring Learning with Errors (RLWE) cryptographic scheme.
///
/// # Type Parameters
///
/// * `F` - A field that supports Number Theoretic Transform (NTT) operations.
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
    /// Creates a new `NttRlweSecretKey` from a coefficient secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A reference to the RLWE secret key.
    /// * `ntt_table` - A reference to the NTT table.
    ///
    /// # Returns
    ///
    /// A new instance of `NttRlweSecretKey` created from the coefficient secret key.
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

    /// Returns the distribution type of the secret key.
    ///
    /// # Returns
    ///
    /// The distribution type of the secret key.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Performs `b-as`.
    pub fn phase(
        &self,
        cipher: NttRlweCiphertext<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> FieldPolynomial<F> {
        let (a_ntt, b_ntt) = cipher.into_inner();
        let a_mul_s_ntt = a_ntt * &self.key;
        let dec_poly_ntt = b_ntt - a_mul_s_ntt;
        dec_poly_ntt.into_coeff_poly(ntt_table)
    }

    /// Encrypts multiple zeros using the secret key.
    ///
    /// # Arguments
    ///
    /// * `zero_count` - The count of zeros to be encrypted.
    /// * `params` - The parameters for the LWE scheme.
    /// * `csrng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A `CmLweCiphertext` containing the encrypted messages.
    pub fn encrypt_multi_zeros<R>(
        &self,
        zero_count: usize,
        params: &RlweParameters<F>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> SparseRlwe<F>
    where
        R: Rng + CryptoRng,
    {
        SparseRlwe::generate_random_zero_sample(
            zero_count,
            &self.key,
            params.noise_distribution(),
            ntt_table,
            rng,
        )
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn decrypt_multi_messages<Msg>(
        &self,
        cipher: &SparseRlwe<F>,
        params: &RlweParameters<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Vec<Msg>
    where
        Msg: TryFrom<<F as Field>::ValueT>,
    {
        let a = cipher.a().clone();
        let a_ntt = a.into_ntt_poly(ntt_table);
        let a_mul_s_ntt = a_ntt * &self.key;
        let a_mul_s = a_mul_s_ntt.into_coeff_poly(ntt_table);

        cipher
            .b()
            .iter()
            .zip(a_mul_s)
            .map(|(x, y)| {
                decode(
                    F::sub(*x, y),
                    params.plain_modulus_value,
                    ModulusValue::Prime(params.modulus),
                )
            })
            .collect()
    }

    /// Decrypts the [`LweCiphertext`] back to message.
    #[inline]
    pub fn phase_multi_messages(
        &self,
        cipher: &SparseRlwe<F>,
        ntt_table: &<F as NttField>::Table,
    ) -> Vec<<F as Field>::ValueT> {
        let a = cipher.a().clone();
        let a_ntt = a.into_ntt_poly(ntt_table);
        let a_mul_s_ntt = a_ntt * &self.key;
        let a_mul_s = a_mul_s_ntt.into_coeff_poly(ntt_table);

        cipher
            .b()
            .iter()
            .zip(a_mul_s)
            .map(|(x, y)| F::sub(*x, y))
            .collect()
    }
}

impl<F: NttField> Size for RlweSecretKey<F> {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    integer::UnsignedInteger,
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial, Polynomial},
    random::{sample_binary_values, BinarySampler, DiscreteGaussian},
    reduce::RingReduce,
    utils::Size,
    Field, NttField,
};
use lattice::{Lwe, NttGadgetRlwe, NttRgsw, NttRlwe, NumRlwe};
use rand::{prelude::Distribution, CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    encode, CmLweCiphertext, LweCiphertext, LweParameters, LweSecretKey, NttRlweSecretKey,
};

/// Represents a public key for the Learning with Errors (LWE) cryptographic scheme.
///
/// # Type Parameters
///
/// * `C` - An unsigned integer type that represents the coefficients of the LWE ciphertexts.
pub struct LwePublicKey<C: UnsignedInteger> {
    public_key: Vec<Lwe<C>>,
}

impl<C: UnsignedInteger> LwePublicKey<C> {
    /// Creates a new `LwePublicKey` using the provided secret key,
    /// parameters, modulus, Gaussian distribution, and random number generator.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A reference to the [LweSecretKey] used to generate the public key.
    /// * `params` - The parameters for the LWE scheme.
    /// * `modulus` - The modulus used for the LWE scheme.
    /// * `gaussian` - The Gaussian distribution used for generating random samples.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `LwePublicKey`.
    #[inline]
    pub fn new<R, Modulus>(
        secret_key: &LweSecretKey<C>,
        params: &LweParameters<C, Modulus>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
        Modulus: RingReduce<C>,
    {
        let gaussian = params.noise_distribution();
        let public_key: Vec<_> = (0..params.dimension)
            .map(|_| {
                Lwe::generate_random_zero_sample(
                    secret_key.as_ref(),
                    params.cipher_modulus,
                    gaussian,
                    rng,
                )
            })
            .collect();

        Self { public_key }
    }

    /// Encrypts a message using the LWE public key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to be encrypted.
    /// * `params` - The parameters for the LWE scheme.
    /// * `modulus` - The modulus used for the LWE scheme.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// An `LweCiphertext` containing the encrypted message.
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
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let r: Vec<C> = sample_binary_values(dimension, rng);

        let mut result = LweCiphertext::zero(dimension);

        modulus.reduce_add_assign(
            result.b_mut(),
            encode(
                message,
                params.plain_modulus_value,
                params.cipher_modulus_value,
            ),
        );

        for (zero, _) in self
            .public_key
            .iter()
            .zip(r.iter())
            .filter(|(_, ri)| ri.is_one())
        {
            result.add_reduce_assign_component_wise(zero, modulus);
        }

        for (ai, ei) in result
            .a_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *rng))
        {
            modulus.reduce_add_assign(ai, ei);
        }
        modulus.reduce_add_assign(result.b_mut(), gaussian.sample(rng));

        result
    }
}

impl<C: UnsignedInteger> Size for LwePublicKey<C> {
    #[inline]
    fn size(&self) -> usize {
        if self.public_key.is_empty() {
            return 0;
        }
        self.public_key.len() * self.public_key[0].size()
    }
}

/// Represents a public key for the Learning with Errors (LWE) cryptographic scheme in RLWE mode.
///
/// # Type Parameters
///
/// * `C` - An unsigned integer type that represents the coefficients of the RLWE ciphertexts.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: UnsignedInteger"))]
pub struct LwePublicKeyRlweMode<C: UnsignedInteger> {
    public_key: NumRlwe<C>,
}

impl<C: UnsignedInteger> LwePublicKeyRlweMode<C> {
    /// Creates a new `LwePublicKeyRlweMode` using the provided secret key,
    /// parameters, modulus, and random number generator.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A reference to the LweSecretKey used to generate the public key.
    /// * `params` - The parameters for the LWE scheme.
    /// * `modulus` - The modulus used for the LWE scheme.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `LwePublicKeyRlweMode`.
    #[inline]
    pub fn new<R, LweModulus>(
        secret_key: &LweSecretKey<C>,
        params: &LweParameters<C, LweModulus>,
        rng: &mut R,
    ) -> LwePublicKeyRlweMode<C>
    where
        R: Rng + CryptoRng,
        LweModulus: RingReduce<C>,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let a = Polynomial::random(modulus.modulus_minus_one(), dimension, rng);
        let mut e = Polynomial::random_gaussian(gaussian, dimension, rng);

        a.naive_mul_inplace(secret_key, modulus, &mut e);

        let public_key = NumRlwe::new(a, e);

        Self { public_key }
    }

    /// Encrypts a message using the public key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to be encrypted.
    /// * `params` - The parameters for the LWE scheme.
    /// * `cipher_modulus` - The modulus used for the LWE scheme.
    /// * `csrng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// An `LweCiphertext` containing the encrypted message.
    #[inline]
    pub fn encrypt<Msg, R, Modulus>(
        &self,
        message: Msg,
        params: &LweParameters<C, Modulus>,
        csrng: &mut R,
    ) -> LweCiphertext<C>
    where
        Msg: TryInto<C>,
        R: Rng + CryptoRng,
        Modulus: RingReduce<C>,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();
        let modulus = params.cipher_modulus;

        let r: Vec<C> = sample_binary_values(dimension, csrng);

        let mut result = NumRlwe::zero(dimension);

        self.public_key
            .a()
            .naive_mul_inplace(&r, modulus, result.a_mut());
        self.public_key
            .b()
            .naive_mul_inplace(&r, modulus, result.b_mut());

        modulus.reduce_add_assign(
            &mut result.b_mut()[0],
            encode(
                message,
                params.plain_modulus_value,
                params.cipher_modulus_value,
            ),
        );

        for (ai, ei) in result
            .a_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(ai, ei);
        }

        for (bi, ei) in result
            .b_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(bi, ei);
        }

        result.extract_lwe_locally(modulus)
    }

    /// Encrypts multiple messages using the public key.
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

        let r: Vec<C> = sample_binary_values(dimension, csrng);

        let mut result = NumRlwe::zero(dimension);

        self.public_key
            .a()
            .naive_mul_inplace(&r, modulus, result.a_mut());
        self.public_key
            .b()
            .naive_mul_inplace(&r, modulus, result.b_mut());

        for (&message, bi) in messages.iter().zip(result.b_mut()) {
            modulus.reduce_add_assign(
                bi,
                encode(
                    message,
                    params.plain_modulus_value,
                    params.cipher_modulus_value,
                ),
            );
        }

        for (ai, ei) in result
            .a_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(ai, ei);
        }

        for (bi, ei) in result
            .b_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(bi, ei);
        }

        result.extract_first_few_lwe_locally(messages.len(), modulus)
    }

    /// Encrypts multiple zeros using the public key.
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

        let r: Vec<C> = sample_binary_values(dimension, csrng);

        let mut result = NumRlwe::zero(dimension);

        self.public_key
            .a()
            .naive_mul_inplace(&r, modulus, result.a_mut());
        self.public_key
            .b()
            .naive_mul_inplace(&r, modulus, result.b_mut());

        for (ai, ei) in result
            .a_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(ai, ei);
        }

        for (bi, ei) in result
            .b_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            modulus.reduce_add_assign(bi, ei);
        }

        result.extract_first_few_lwe_locally(zero_count, modulus)
    }
}

impl<C: UnsignedInteger> Size for LwePublicKeyRlweMode<C> {
    #[inline]
    fn size(&self) -> usize {
        self.public_key.size()
    }
}

/// Represents a public key for the NTT RLWE cryptographic scheme.
///
/// # Type Parameters
///
/// * `F` - A field that supports Number Theoretic Transform (NTT) operations.
pub struct NttRlwePublicKey<F: NttField> {
    key: NttRlwe<F>,
}

impl<F: NttField> Clone for NttRlwePublicKey<F> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
        }
    }
}

impl<F: NttField> NttRlwePublicKey<F> {
    /// Creates a new [`NttRlwePublicKey`] using the provided secret key, Gaussian distribution, NTT table, and random number generator.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A reference to the NttRlweSecretKey used to generate the public key.
    /// * `gaussian` - The Gaussian distribution used for generating random samples.
    /// * `ntt_table` - The NTT table used for Number Theoretic Transform operations.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of [`NttRlwePublicKey`].
    pub fn new<R>(
        secret_key: &NttRlweSecretKey<F>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> NttRlwePublicKey<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = secret_key.coeff_count();

        let a = FieldNttPolynomial::random(dimension, rng);
        let mut b =
            FieldPolynomial::random_gaussian(dimension, gaussian, rng).into_ntt_poly(ntt_table);

        b.add_mul_assign(&a, secret_key);

        Self {
            key: NttRlwe::new(a, b),
        }
    }

    /// Returns a reference to the key of this [`NttRlwePublicKey<F>`].
    #[inline]
    pub fn key(&self) -> &NttRlwe<F> {
        &self.key
    }

    /// Encrypts a message using the NTT RLWE public key.
    ///
    /// # Arguments
    ///
    /// * `_message` - The message to be encrypted.
    ///
    /// # Type Parameters
    ///
    /// * `R` - A random number generator that implements `Rng` and `CryptoRng`.
    pub fn encrypt<R>(
        &self,
        message: &FieldPolynomial<F>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> NttRlwe<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = ntt_table.dimension();

        let v = <FieldPolynomial<F>>::random_binary(dimension, rng);
        let e0 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);
        let e1 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);

        let mut v = ntt_table.transform_inplace(v);
        let mut e0 = ntt_table.transform_inplace(e0);
        let mut e1 = ntt_table.transform_inplace(e1);

        e0.add_mul_assign(self.key().a(), &v);
        e1.add_mul_assign(self.key().b(), &v);

        v.copy_from(message);
        ntt_table.transform_slice(v.as_mut_slice());
        e1 += v;

        NttRlwe::new(e0, e1)
    }

    fn encrypt_monomial_inner<R>(
        &self,
        coeff: <F as Field>::ValueT,
        degree: usize,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
        v: &mut FieldNttPolynomial<F>,
    ) -> NttRlwe<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = ntt_table.dimension();

        v.iter_mut()
            .zip(BinarySampler.sample_iter(&mut *rng))
            .for_each(
                |(a, b): (&mut <F as Field>::ValueT, <F as Field>::ValueT)| {
                    *a = b;
                },
            );
        let e0 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);
        let mut e1 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);
        F::add_assign(&mut e1[degree], coeff);

        ntt_table.transform_slice(v.as_mut_slice());
        let mut e0 = ntt_table.transform_inplace(e0);
        let mut e1 = ntt_table.transform_inplace(e1);

        e0.add_mul_assign(self.key().a(), v);
        e1.add_mul_assign(self.key().b(), v);

        NttRlwe::new(e0, e1)
    }

    fn encrypt_neg_secret_monomial_inner<R>(
        &self,
        coeff: <F as Field>::ValueT,
        degree: usize,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
        v: &mut FieldNttPolynomial<F>,
    ) -> NttRlwe<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = ntt_table.dimension();

        v.iter_mut()
            .zip(BinarySampler.sample_iter(&mut *rng))
            .for_each(
                |(a, b): (&mut <F as Field>::ValueT, <F as Field>::ValueT)| {
                    *a = b;
                },
            );
        let mut e0 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);
        let e1 = <FieldPolynomial<F>>::random_gaussian(dimension, gaussian, rng);
        F::add_assign(&mut e0[degree], coeff);

        ntt_table.transform_slice(v.as_mut_slice());
        let mut e0 = ntt_table.transform_inplace(e0);
        let mut e1 = ntt_table.transform_inplace(e1);

        e0.add_mul_assign(self.key().a(), v);
        e1.add_mul_assign(self.key().b(), v);

        NttRlwe::new(e0, e1)
    }

    /// Generate a RGSW ciphertext which encrypted `coeff*X^degree`.
    pub fn encrypt_monomial_rgsw<R>(
        &self,
        coeff: <F as Field>::ValueT,
        degree: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> NttRgsw<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = ntt_table.dimension();

        let mut v = <FieldNttPolynomial<F>>::zero(dimension);
        let m: Vec<NttRlwe<F>> = basis
            .scalar_iter()
            .map(|scalar| {
                self.encrypt_monomial_inner(
                    F::mul(coeff, scalar),
                    degree,
                    gaussian,
                    ntt_table,
                    rng,
                    &mut v,
                )
            })
            .collect();

        let minus_s_m: Vec<NttRlwe<F>> = basis
            .scalar_iter()
            .map(|scalar| {
                self.encrypt_neg_secret_monomial_inner(
                    F::mul(coeff, scalar),
                    degree,
                    gaussian,
                    ntt_table,
                    rng,
                    &mut v,
                )
            })
            .collect();

        NttRgsw::new(
            <NttGadgetRlwe<F>>::new(minus_s_m, basis),
            <NttGadgetRlwe<F>>::new(m, basis),
        )
    }
}

impl<F: NttField> Size for NttRlwePublicKey<F> {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}

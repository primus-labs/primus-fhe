use algebra::{
    integer::UnsignedInteger,
    polynomial::{FieldNttPolynomial, FieldPolynomial, NumPolynomial},
    random::{sample_binary_values, DiscreteGaussian},
    reduce::{
        Modulus, ReduceAdd, ReduceAddAssign, ReduceDotProduct, ReduceMul, ReduceSubAssign,
        RingReduce,
    },
    Field, NttField,
};
use lattice::{Lwe, NttRlwe, NumRlwe};
use rand::{prelude::Distribution, CryptoRng, Rng};

use crate::{
    encode, CmLweCiphertext, LweCiphertext, LweParameters, LweSecretKey, NttRlweSecretKey,
};

pub struct LwePublicKey<C: UnsignedInteger> {
    public_key: Vec<Lwe<C>>,
}

impl<C: UnsignedInteger> LwePublicKey<C> {
    #[inline]
    pub fn new<M, R>(
        secret_key: &LweSecretKey<C>,
        params: &LweParameters<C>,
        modulus: M,
        gaussian: DiscreteGaussian<C>,
        rng: &mut R,
    ) -> Self
    where
        M: Copy + Modulus<C> + ReduceDotProduct<C, Output = C> + ReduceAdd<C, Output = C>,
        R: Rng + CryptoRng,
    {
        let public_key: Vec<_> = (0..params.dimension)
            .map(|_| Lwe::generate_random_zero_sample(secret_key.as_ref(), modulus, gaussian, rng))
            .collect();

        Self { public_key }
    }

    #[inline]
    pub fn encrypt<M, R>(
        &self,
        message: M,
        params: &LweParameters<C>,
        modulus: impl RingReduce<C>,
        rng: &mut R,
    ) -> LweCiphertext<C>
    where
        M: TryInto<C>,
        R: Rng + CryptoRng,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();

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

        for (zero, &ri) in self.public_key.iter().zip(r.iter()) {
            result.add_assign_rhs_mul_scalar_reduce(zero, ri, modulus);
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

pub struct LwePublicKeyRlweMode<C: UnsignedInteger> {
    public_key: NumRlwe<C>,
}

impl<C: UnsignedInteger> LwePublicKeyRlweMode<C> {
    #[inline]
    pub fn new<M, R>(
        secret_key: &LweSecretKey<C>,
        params: &LweParameters<C>,
        modulus: M,
        rng: &mut R,
    ) -> LwePublicKeyRlweMode<C>
    where
        M: Copy + Modulus<C> + ReduceAddAssign<C> + ReduceSubAssign<C> + ReduceMul<C, Output = C>,
        R: Rng + CryptoRng,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();

        let a = NumPolynomial::random(dimension, modulus, rng);
        let mut e = NumPolynomial::random_gaussian(dimension, gaussian, rng);

        a.naive_mul_inplace(secret_key, modulus, &mut e);

        let public_key = NumRlwe::new(a, e);

        Self { public_key }
    }

    #[inline]
    pub fn encrypt<M, R>(
        &self,
        message: M,
        params: &LweParameters<C>,
        cipher_modulus: impl RingReduce<C>,
        csrng: &mut R,
    ) -> LweCiphertext<C>
    where
        M: TryInto<C>,
        R: Rng + CryptoRng,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();

        let r: Vec<C> = sample_binary_values(dimension, csrng);

        let mut result = NumRlwe::zero(dimension);

        self.public_key
            .a()
            .naive_mul_inplace(&r, cipher_modulus, result.a_mut());
        self.public_key
            .b()
            .naive_mul_inplace(&r, cipher_modulus, result.b_mut());

        cipher_modulus.reduce_add_assign(
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
            cipher_modulus.reduce_add_assign(ai, ei);
        }

        for (bi, ei) in result
            .b_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            cipher_modulus.reduce_add_assign(bi, ei);
        }

        result.extract_lwe_locally(cipher_modulus)
    }

    #[inline]
    pub fn encrypt_multi_messages<M, R>(
        &self,
        messages: &[M],
        params: &LweParameters<C>,
        cipher_modulus: impl RingReduce<C>,
        csrng: &mut R,
    ) -> CmLweCiphertext<C>
    where
        M: Copy + TryInto<C>,
        R: Rng + CryptoRng,
    {
        let dimension = params.dimension;
        let gaussian = params.noise_distribution();

        let r: Vec<C> = sample_binary_values(dimension, csrng);

        let mut result = NumRlwe::zero(dimension);

        self.public_key
            .a()
            .naive_mul_inplace(&r, cipher_modulus, result.a_mut());
        self.public_key
            .b()
            .naive_mul_inplace(&r, cipher_modulus, result.b_mut());

        for (&message, bi) in messages.iter().zip(result.b_mut()) {
            cipher_modulus.reduce_add_assign(
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
            cipher_modulus.reduce_add_assign(ai, ei);
        }

        for (bi, ei) in result
            .b_mut()
            .iter_mut()
            .zip(gaussian.sample_iter(&mut *csrng))
        {
            cipher_modulus.reduce_add_assign(bi, ei);
        }

        result.extract_first_few_lwe_locally(messages.len(), cipher_modulus)
    }
}

/// public key
pub struct NttRlwePublicKey<F: NttField> {
    key: NttRlwe<F>,
}

impl<F: NttField> NttRlwePublicKey<F> {
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

    pub fn encrypt<R>(_message: &FieldPolynomial<F>)
    where
        R: Rng + CryptoRng,
    {
        todo!()
    }
}

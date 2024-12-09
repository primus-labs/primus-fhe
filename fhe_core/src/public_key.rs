use algebra::{
    ntt_add_mul_assign, Field, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial,
};
use lattice::{NTTRLWE, RLWE};
use rand::{CryptoRng, Rng};

use crate::{NTTRLWESecretKey, RLWESecretKey};

/// public key
pub struct NTTRLWEPublicKey<F: NTTField> {
    key: NTTRLWE<F>,
}

impl<F: NTTField> NTTRLWEPublicKey<F> {
    ///
    pub fn new<R>(
        rlwe_secret_key: &NTTRLWESecretKey<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        csrng: &mut R,
    ) -> NTTRLWEPublicKey<F>
    where
        R: Rng + CryptoRng,
    {
        let dimension = rlwe_secret_key.coeff_count();
        let a = NTTPolynomial::random(dimension, csrng);

        let mut b =
            Polynomial::random_with_gaussian(dimension, csrng, error_sampler).into_ntt_polynomial();
        ntt_add_mul_assign(&mut b, &a, rlwe_secret_key);

        Self {
            key: NTTRLWE::new(a, b),
        }
    }

    /// Returns a reference to the key of this [`NTTRLWEPublicKey<F>`].
    pub fn key(&self) -> &NTTRLWE<F> {
        &self.key
    }
}

/// public key
pub struct RLWEPublicKey<F: Field> {
    key: RLWE<F>,
}

impl<F: Field> RLWEPublicKey<F> {
    ///
    #[inline]
    pub fn new<R: Rng + CryptoRng>(
        rlwe_secret_key: &RLWESecretKey<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        csrng: &mut R,
    ) -> RLWEPublicKey<F> {
        let dimension = rlwe_secret_key.coeff_count();
        let a = Polynomial::random(dimension, csrng);

        let mut b = Polynomial::random_with_gaussian(dimension, csrng, error_sampler);

        a.normal_mul_inplace(rlwe_secret_key, &mut b);

        Self {
            key: RLWE::new(a, b),
        }
    }

    /// Returns a reference to the key of this [`RLWEPublicKey<F>`].
    #[inline]
    pub fn key(&self) -> &RLWE<F> {
        &self.key
    }
}

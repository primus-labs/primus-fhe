use algebra::{FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial};
use lattice::RLWE;
use rand::{CryptoRng, Rng};

use crate::NTTRingSecretKey;

/// public key
pub struct RLWEPublicKey<F> {
    key: RLWE<F>,
}

impl<F: NTTField> RLWEPublicKey<F> {
    ///
    pub fn new<R: Rng + CryptoRng>(
        ntt_ring_secret_key: &NTTRingSecretKey<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        csrng: &mut R,
    ) -> RLWEPublicKey<F> {
        let dimension = ntt_ring_secret_key.coeff_count();
        let a = NTTPolynomial::random(dimension, csrng);
        let a_s = (&a * ntt_ring_secret_key).into_native_polynomial();
        let e = Polynomial::random_with_gaussian(dimension, csrng, error_sampler);

        Self {
            key: RLWE::new(a.into_native_polynomial(), a_s + e),
        }
    }

    /// Returns a reference to the key of this [`RLWEPublicKey<F>`].
    pub fn key(&self) -> &RLWE<F> {
        &self.key
    }
}

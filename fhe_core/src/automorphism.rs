use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, NTTRLWESpace, PolynomialSpace, RLWESpace};
use num_traits::One;
use rand::{CryptoRng, Rng};

use crate::{NTTRLWESecretKey, RLWECiphertext, RLWESecretKey};

///
pub struct AutoKey<F: NTTField> {
    key: NTTGadgetRLWE<F>,
    degree: usize,
}

impl<F: NTTField> AutoKey<F> {
    /// Creates a new [`AutoKey<F>`].
    #[inline]
    pub fn new(key: NTTGadgetRLWE<F>, degree: usize) -> Self {
        Self { key, degree }
    }

    ///
    #[inline]
    pub fn new_with_secret_key<R>(
        sk: &RLWESecretKey<F>,
        ntt_sk: &NTTRLWESecretKey<F>,
        degree: usize,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = sk.coeff_count();
        assert!(degree > 0 && degree < rlwe_dimension << 1);
        let key = if degree.is_one() {
            NTTGadgetRLWE::generate_random_neg_secret_sample(ntt_sk, basis, error_sampler, rng)
        } else {
            let p_auto = poly_auto(sk, degree, rlwe_dimension);
            let auto_sk = (-p_auto).into_ntt_polynomial();
            NTTGadgetRLWE::generate_random_poly_sample(ntt_sk, &auto_sk, basis, error_sampler, rng)
        };
        Self { key, degree }
    }

    ///
    pub fn automorphism(&self, ciphertext: &RLWECiphertext<F>) -> RLWECiphertext<F> {
        let rlwe_dimension = ciphertext.dimension();

        let a = poly_auto(ciphertext.a(), self.degree, rlwe_dimension);

        let r = self.key.mul_polynomial(&a);

        let mut r = <RLWECiphertext<F>>::from(r);

        poly_auto_inplace(ciphertext.b(), self.degree, rlwe_dimension, r.b_mut());

        r
    }

    ///
    pub fn automorphism_inplace(
        &self,
        ciphertext: &RLWECiphertext<F>,
        // Pre allocate space for decomposition
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        ntt_rlwe_space: &mut NTTRLWESpace<F>,
        // Output destination
        destination: &mut RLWECiphertext<F>,
    ) {
        let rlwe_dimension = ciphertext.dimension();

        destination.a_mut().set_zero();
        poly_auto_inplace(
            ciphertext.a(),
            self.degree,
            rlwe_dimension,
            destination.a_mut(),
        );

        self.key.mul_polynomial_inplace(
            destination.a(),
            decompose_space,
            polynomial_space,
            ntt_rlwe_space,
        );

        ntt_rlwe_space.inverse_transform_inplace(destination);

        poly_auto_inplace(
            ciphertext.b(),
            self.degree,
            rlwe_dimension,
            destination.b_mut(),
        );
    }
}

#[inline]
fn poly_auto<F: NTTField>(
    poly: &Polynomial<F>,
    degree: usize,
    rlwe_dimension: usize,
) -> Polynomial<F> {
    let mut res = Polynomial::zero(rlwe_dimension);
    poly_auto_inplace(poly, degree, rlwe_dimension, &mut res);
    res
}

#[inline]
fn poly_auto_inplace<F: NTTField>(
    poly: &Polynomial<F>,
    degree: usize,
    rlwe_dimension: usize,
    destination: &mut Polynomial<F>,
) {
    let twice_dimension = rlwe_dimension << 1;
    for (i, c) in poly.iter().enumerate() {
        let j = i.checked_mul(degree).unwrap() % twice_dimension;
        if j < rlwe_dimension {
            destination[j] += *c;
        } else {
            destination[j - rlwe_dimension] += -*c;
        }
    }
}

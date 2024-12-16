use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField, Polynomial};
use lattice::NTTGadgetRLWE;
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
        let b = poly_auto(ciphertext.b(), self.degree, rlwe_dimension);

        let r = self.key.mul_polynomial(&a);

        let mut r = <RLWECiphertext<F>>::from(r);

        *r.b_mut() += b;

        r
    }
}

fn poly_auto<F: NTTField>(
    a: &Polynomial<F>,
    degree: usize,
    rlwe_dimension: usize,
) -> Polynomial<F> {
    let mut res = Polynomial::zero(rlwe_dimension);
    let twice_dimension = rlwe_dimension << 1;
    res[0] = a[0];
    for (i, c) in a[1..].iter().enumerate() {
        let j = ((i + 1) * degree) % twice_dimension;
        if j < twice_dimension {
            res[j] += *c;
        } else {
            res[j - rlwe_dimension] += -*c;
        }
    }
    res
}

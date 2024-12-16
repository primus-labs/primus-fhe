use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField, Polynomial};
use lattice::{DecompositionSpace, NTTGadgetRLWE, NTTRLWESpace, PolynomialSpace};
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

#[cfg(test)]
mod tests {
    use algebra::{Field, ModulusConfig};
    use lattice::RLWE;
    use rand::{distributions::Uniform, prelude::Distribution};

    use crate::DefaultFieldU32;

    use super::*;

    type FF = DefaultFieldU32;
    type Inner = u32; // inner type
    type PolyFF = Polynomial<FF>;

    const FP: Inner = FF::MODULUS.value(); // ciphertext space
    const FT: Inner = 8; // message space

    const N: usize = 1024;

    #[inline]
    fn encode(m: Inner) -> FF {
        FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
    }

    #[inline]
    fn decode(c: FF) -> Inner {
        (c.value() as f64 * FT as f64 / FP as f64).round() as Inner % FT
    }

    #[test]
    fn test_auto() {
        let csrng = &mut rand::thread_rng();

        let poly = <Polynomial<FF>>::random_with_ternary(N, csrng);
        let result = poly_auto(&poly, N + 1, N);

        let flag = result
            .iter()
            .zip(poly.iter())
            .enumerate()
            .all(|(i, (&r, &p))| if i % 2 == 1 { r == -p } else { r == p });

        assert!(flag);
    }

    #[test]
    fn test_he_auto() {
        let mut csrng = rand::thread_rng();
        let error_sampler = FieldDiscreteGaussianSampler::new(0.0, 3.2).unwrap();
        let dis = Uniform::new(0, FT);

        let sk = <Polynomial<FF>>::random_with_ternary(N, &mut csrng);
        let ntt_sk = sk.clone().into_ntt_polynomial();

        let values: Vec<Inner> = dis.sample_iter(&mut csrng).take(N).collect();
        let encoded_values = PolyFF::new(values.iter().copied().map(encode).collect());

        let mut cipher =
            <RLWE<FF>>::generate_random_zero_sample(&ntt_sk, error_sampler, &mut csrng);
        *cipher.b_mut() += &encoded_values;

        let auto_key = AutoKey::new_with_secret_key(
            &sk,
            &ntt_sk,
            N + 1,
            Basis::new(1),
            error_sampler,
            &mut csrng,
        );
        let result = auto_key.automorphism(&cipher);

        let decrypted_values = (result.b() - result.a() * &ntt_sk)
            .into_iter()
            .map(decode)
            .collect::<Vec<u32>>();

        let flag = decrypted_values
            .iter()
            .zip(values.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    (r + p) % FT == 0
                } else {
                    r == p
                }
            });

        assert!(flag);
    }
}

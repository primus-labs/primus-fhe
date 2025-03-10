use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    modulus::PowOf2Modulus,
    ntt::NumberTheoryTransform,
    polynomial::FieldPolynomial,
    random::DiscreteGaussian,
    reduce::{ReduceAddAssign, ReduceMul, ReduceSubAssign},
    utils::Size,
    Field, NttField,
};
use lattice::{
    utils::{NttRlweSpace, PolyDecomposeSpace},
    NttGadgetRlwe,
};
use num_traits::One;
use rand::{CryptoRng, Rng};

use crate::{NttRlweSecretKey, RlweCiphertext, RlweSecretKey};

/// Automorphism key
pub struct AutoKey<F: NttField> {
    degree: usize,
    key: NttGadgetRlwe<F>,
    ntt_table: Arc<<F as NttField>::Table>,
}

/// Preallocated space for automorphism
pub struct AutoSpace<F: NttField> {
    decompose_space: PolyDecomposeSpace<F>,
    ntt_rlwe_space: NttRlweSpace<F>,
}

impl<F: NttField> AutoSpace<F> {
    /// Creates a new [`AutoSpace<F>`].
    #[inline]
    pub fn new(dimension: usize) -> Self {
        Self {
            decompose_space: PolyDecomposeSpace::new(dimension),
            ntt_rlwe_space: NttRlweSpace::new(dimension),
        }
    }
}

impl<F: NttField> AutoKey<F> {
    /// Creates a new [`AutoKey<F>`].
    #[inline]
    pub fn new<R>(
        secret_key: &RlweSecretKey<F>,
        ntt_secret_key: &NttRlweSecretKey<F>,
        degree: usize,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        assert!(degree > 0 && degree < rlwe_dimension << 1);
        let key = if degree.is_one() {
            NttGadgetRlwe::generate_random_neg_secret_sample(
                ntt_secret_key,
                basis,
                gaussian,
                &ntt_table,
                rng,
            )
        } else {
            let p_auto = poly_auto(secret_key, degree, rlwe_dimension);
            let auto_sk = ntt_table.transform_inplace(-p_auto);
            NttGadgetRlwe::generate_random_poly_sample(
                ntt_secret_key,
                &auto_sk,
                basis,
                gaussian,
                &ntt_table,
                rng,
            )
        };

        Self {
            key,
            ntt_table,
            degree,
        }
    }

    /// Performs automorphism on the given RLWE ciphertext.
    #[inline]
    pub fn automorphism(&self, ciphertext: &RlweCiphertext<F>) -> RlweCiphertext<F> {
        let rlwe_dimension = ciphertext.dimension();

        let a = poly_auto(ciphertext.a(), self.degree, rlwe_dimension);

        let mut result = self
            .key
            .mul_polynomial(&a, &self.ntt_table)
            .to_rlwe(&self.ntt_table);

        poly_auto_inplace(ciphertext.b(), self.degree, rlwe_dimension, result.b_mut());

        result
    }

    /// Performs automorphism on the given RLWE ciphertext in place.
    pub fn automorphism_inplace(
        &self,
        ciphertext: &RlweCiphertext<F>,
        auto_space: &mut AutoSpace<F>,
        destination: &mut RlweCiphertext<F>,
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
            &self.ntt_table,
            &mut auto_space.decompose_space,
            &mut auto_space.ntt_rlwe_space,
        );

        auto_space
            .ntt_rlwe_space
            .inverse_transform_inplace(&self.ntt_table, destination);

        poly_auto_inplace(
            ciphertext.b(),
            self.degree,
            rlwe_dimension,
            destination.b_mut(),
        );
    }
}

impl<F: NttField> Size for AutoKey<F> {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}

#[inline]
fn poly_auto<F: NttField>(
    poly: &FieldPolynomial<F>,
    degree: usize,
    dimension: usize,
) -> FieldPolynomial<F> {
    let mut res = FieldPolynomial::zero(dimension);
    poly_auto_inplace(poly, degree, dimension, &mut res);
    res
}

#[inline]
fn poly_auto_inplace<F: NttField>(
    poly: &FieldPolynomial<F>,
    degree: usize,
    dimension: usize,
    destination: &mut FieldPolynomial<F>,
) {
    let twice_dimension = dimension << 1;
    let modulus = <PowOf2Modulus<usize>>::new(twice_dimension);
    for (i, c) in poly.iter().enumerate() {
        let j = modulus.reduce_mul(i, degree);
        if j < dimension {
            F::MODULUS.reduce_add_assign(&mut destination[j], *c);
        } else {
            F::MODULUS.reduce_sub_assign(&mut destination[j - dimension], *c);
        }
    }
}

#[cfg(test)]
mod tests {
    use algebra::{reduce::ReduceNeg, Field, U32FieldEval};
    use lattice::Rlwe;
    use rand::{distributions::Uniform, prelude::Distribution};

    use super::*;

    type Fp = U32FieldEval<132120577>;
    type ValT = u32; // inner type
    type PolyT = FieldPolynomial<Fp>;

    const CIPHER_MODULUS: ValT = <Fp as Field>::MODULUS_VALUE; // ciphertext space
    const PLAIN_MODULUS: ValT = 8; // message space

    const LOG_N: u32 = 10;
    const N: usize = 1 << LOG_N;

    #[inline]
    fn encode(m: ValT) -> ValT {
        (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
    }

    #[inline]
    fn decode(c: ValT) -> ValT {
        (c as f64 * PLAIN_MODULUS as f64 / CIPHER_MODULUS as f64).round() as ValT % PLAIN_MODULUS
    }

    #[test]
    fn test_auto() {
        let mut rng = rand::thread_rng();

        let poly = PolyT::random_ternary(N, &mut rng);
        let result = poly_auto(&poly, N + 1, N);

        let flag = result
            .iter()
            .zip(poly.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    r == Fp::MODULUS.reduce_neg(p)
                } else {
                    r == p
                }
            });

        assert!(flag);
    }

    #[test]
    fn test_he_auto() {
        let mut rng = rand::thread_rng();

        let ntt_table = Arc::new(Fp::generate_ntt_table(LOG_N).unwrap());
        let distr = Uniform::new(0, PLAIN_MODULUS);

        let sk = RlweSecretKey::new(
            PolyT::random_ternary(N, &mut rng),
            crate::RingSecretKeyType::Ternary,
        );
        let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);
        let gaussian = DiscreteGaussian::new(0.0, 3.2, Fp::MINUS_ONE).unwrap();
        let basis = NonPowOf2ApproxSignedBasis::new(Fp::MODULUS_VALUE, 4, None);

        let values: Vec<ValT> = distr.sample_iter(&mut rng).take(N).collect();
        let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

        let mut cipher =
            <Rlwe<Fp>>::generate_random_zero_sample(&ntt_sk, gaussian, &ntt_table, &mut rng);
        *cipher.b_mut() += &encoded_values;

        let auto_key = AutoKey::new(
            &sk,
            &ntt_sk,
            N + 1,
            &basis,
            gaussian,
            Arc::clone(&ntt_table),
            &mut rng,
        );
        let result = auto_key.automorphism(&cipher);

        let decrypted_values = (result.b()
            - ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &*ntt_sk))
        .into_iter()
        .map(decode)
        .collect::<Vec<u32>>();

        let flag = decrypted_values
            .iter()
            .zip(values.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    (r + p) % PLAIN_MODULUS == 0
                } else {
                    r == p
                }
            });

        assert!(flag);
    }
}

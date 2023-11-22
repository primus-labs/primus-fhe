use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Poly, Polynomial},
};

use crate::RLWE;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`GadgetRLWE`] stores a sequence of `RLWE` ciphertexts where each [`RLWE<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the `NTTField` trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
///
/// # Fields
/// * `data: Vec<RLWE<F>>` - A vector of RLWE ciphertexts, each encrypted message with a different power of the `basis`.
/// * `basis: F::Base` - The base with respect to which the ciphertexts are scaled.
#[derive(Debug, Clone)]
pub struct GadgetRLWE<F: NTTField> {
    data: Vec<RLWE<F>>,
    basis: F::Base,
}

impl<F: NTTField> From<(Vec<RLWE<F>>, F::Base)> for GadgetRLWE<F> {
    fn from((data, basis): (Vec<RLWE<F>>, F::Base)) -> Self {
        Self { data, basis }
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: F::Base) -> Self {
        Self { data, basis }
    }

    /// Creates a new [`GadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[RLWE<F>], basis: F::Base) -> Self {
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Returns a reference to the `data` of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[RLWE<F>] {
        self.data.as_ref()
    }

    /// Returns the basis of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn basis(&self) -> F::Base {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, RLWE<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`GadgetRLWE<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, RLWE<F>> {
        self.data.iter_mut()
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_polynomial(&self, poly: &Polynomial<F>) -> RLWE<F> {
        let decomposed = poly.decompose(self.basis);
        self.mul_with_decomposed_polynomial(&decomposed)
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_decomposed_polynomial(&self, decomposed: &[Polynomial<F>]) -> RLWE<F> {
        assert_eq!(self.data().len(), decomposed.len());

        let coeff_count = decomposed[0].coeff_count();

        self.data()
            .iter()
            .zip(decomposed)
            .fold(RLWE::zero(coeff_count), |acc, (r, p)| {
                acc.add_element_wise(&r.clone().mul_with_polynomial(p))
            })
    }

    /// Convert this [`GadgetRLWE<F>`] to [`NTTPolynomial<F>`] vector.
    #[inline]
    pub(crate) fn to_ntt_poly(&self) -> Vec<(NTTPolynomial<F>, NTTPolynomial<F>)> {
        self.iter()
            .map(|rlwe| (rlwe.a().into(), rlwe.b().into()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use algebra::field::{BarrettConfig, FieldDistribution, Fp32};
    use rand::{distributions::Standard, prelude::*};

    use super::*;

    #[test]
    fn test_gadget_rlwe() {
        #[inline]
        fn min_to_zero(value: Fp32) -> u32 {
            value.inner().min(P - value.inner())
        }

        #[inline]
        fn decode(c: Fp32) -> u32 {
            (c.inner() as f64 * T as f64 / P as f64).round() as u32 % T
        }

        const P: u32 = Fp32::BARRETT_MODULUS.value();
        const N: usize = 1 << 3;
        const BASE: u32 = 1 << 1;
        const T: u32 = 128;

        let rng = &mut rand::thread_rng();
        let chi = Fp32::normal_distribution(0., 3.2).unwrap();

        let m = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
        let poly = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let poly_mul_m = &poly * &m;

        let s = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());

        let decompose_len = Fp32::decompose_len(BASE);

        let m_base_power = (0..decompose_len)
            .map(|i| {
                let a = Polynomial::new(rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>());
                let e = Polynomial::new(rng.sample_iter(chi).take(N).collect::<Vec<Fp32>>());
                let b = &a * &s + m.mul_scalar(BASE.pow(i as u32)) + e;

                RLWE::new(a, b)
            })
            .collect::<Vec<RLWE<Fp32>>>();

        let bad_rlwe_mul = m_base_power[0].clone().mul_with_polynomial(&poly);
        let bad_mul = bad_rlwe_mul.b() - bad_rlwe_mul.a() * &s;

        let gadget_rlwe = GadgetRLWE::new(m_base_power, BASE);

        let good_rlwe_mul = gadget_rlwe.mul_with_polynomial(&poly);
        let good_mul = good_rlwe_mul.b() - good_rlwe_mul.a() * s;

        let diff: Vec<u32> = (&poly_mul_m - &good_mul)
            .into_iter()
            .map(min_to_zero)
            .collect();

        let bad_diff: Vec<u32> = (&poly_mul_m - &bad_mul)
            .into_iter()
            .map(min_to_zero)
            .collect();

        let diff_std_dev = diff
            .into_iter()
            .fold(0., |acc, v| acc + (v as f64) * (v as f64))
            .sqrt();

        let bad_diff_std_dev = bad_diff
            .into_iter()
            .fold(0., |acc, v| acc + (v as f64) * (v as f64))
            .sqrt();

        assert!(diff_std_dev < bad_diff_std_dev);

        let decrypted: Vec<u32> = good_mul.into_iter().map(decode).collect();
        let decoded: Vec<u32> = poly_mul_m.into_iter().map(decode).collect();
        assert_eq!(decrypted, decoded);
    }
}

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
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

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: F::Base) -> Self {
        Self { data, basis }
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

        match (self.data(), decomposed) {
            ([first_rlwe, other_rlwes @ ..], [first_poly, other_polys @ ..]) => {
                let init = first_rlwe.clone().mul_with_polynomial(first_poly);

                other_rlwes
                    .iter()
                    .zip(other_polys)
                    .fold(init, |acc, (r, p)| {
                        acc.add_element_wise(&r.clone().mul_with_polynomial(p))
                    })
            }
            _ => unreachable!(),
        }
    }

    /// Convert this [`GadgetRLWE<F>`] to [`NTTPolynomial<F>`] vector.
    #[inline]
    pub(crate) fn to_ntt_poly(&self) -> Vec<(NTTPolynomial<F>, NTTPolynomial<F>)> {
        self.iter()
            .map(|rlwe| (rlwe.a().into(), rlwe.b().into()))
            .collect()
    }
}

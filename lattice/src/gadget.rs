use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use crate::RLWE;

/// A special RLWE type, which stores a message with different basis.
#[derive(Clone)]
pub struct GadgetRLWE<F: NTTField> {
    data: Vec<RLWE<F>>,
    basis: F::Modulus,
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: F::Modulus) -> Self {
        Self { data, basis }
    }

    /// Returns a reference to the `data` of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[RLWE<F>] {
        self.data.as_ref()
    }

    /// Returns a reference to the basis of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn basis(&self) -> &F::Modulus {
        &self.basis
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
        let decomposed = poly.decompose(self.basis.clone());
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

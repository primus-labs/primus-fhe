use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use crate::{NTTRLWE, RLWE};

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
#[derive(Debug, Clone)]
pub struct GadgetRLWE<F: NTTField> {
    /// A vector of RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<RLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: usize,
}

impl<F: NTTField> From<(Vec<RLWE<F>>, usize)> for GadgetRLWE<F> {
    fn from((data, basis): (Vec<RLWE<F>>, usize)) -> Self {
        Self { data, basis }
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: usize) -> Self {
        Self { data, basis }
    }

    /// Creates a new [`GadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[RLWE<F>], basis: usize) -> Self {
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
    pub fn basis(&self) -> usize {
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

        self.data
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

/// ntt gadget rlwe
#[derive(Debug, Clone)]
pub struct NTTGadgetRLWE<F: NTTField> {
    /// A vector of NTT RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NTTRLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: usize,
}

impl<F: NTTField> From<GadgetRLWE<F>> for NTTGadgetRLWE<F> {
    #[inline]
    fn from(g: GadgetRLWE<F>) -> Self {
        Self {
            data: g.data.into_iter().map(<NTTRLWE<F>>::from).collect(),
            basis: g.basis,
        }
    }
}

impl<F: NTTField> From<(Vec<NTTRLWE<F>>, usize)> for NTTGadgetRLWE<F> {
    #[inline]
    fn from((data, basis): (Vec<NTTRLWE<F>>, usize)) -> Self {
        Self { data, basis }
    }
}

impl<F: NTTField> NTTGadgetRLWE<F> {
    /// Creates a new [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<NTTRLWE<F>>, basis: usize) -> Self {
        Self { data, basis }
    }

    /// Creates a new [`NTTGadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[NTTRLWE<F>], basis: usize) -> Self {
        Self {
            data: data.to_vec(),
            basis,
        }
    }

    /// Returns a reference to the data of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[NTTRLWE<F>] {
        self.data.as_ref()
    }

    /// Returns the basis of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn basis(&self) -> usize {
        self.basis
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_polynomial(&self, poly: &Polynomial<F>) -> RLWE<F> {
        let decomposed = poly.decompose(self.basis);
        self.mul_with_decomposed_polynomial(&decomposed)
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_with_decomposed_polynomial(&self, decomposed: &[Polynomial<F>]) -> RLWE<F> {
        assert_eq!(self.data().len(), decomposed.len());

        let coeff_count = decomposed[0].coeff_count();

        self.data()
            .iter()
            .zip(decomposed)
            .fold(RLWE::zero(coeff_count), |acc, (g, d)| {
                acc.add_element_wise(&g.mul_with_polynomial(d))
            })
    }
}

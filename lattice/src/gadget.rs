use algebra::{Basis, NTTField, Polynomial};

use crate::{NTTRLWE, RLWE};

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`GadgetRLWE`] stores a sequence of [`RLWE`] ciphertexts where each [`RLWE<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Debug, Clone)]
pub struct GadgetRLWE<F: NTTField> {
    /// A vector of RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<RLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
}

impl<F: NTTField> From<(Vec<RLWE<F>>, Basis<F>)> for GadgetRLWE<F> {
    #[inline]
    fn from((data, basis): (Vec<RLWE<F>>, Basis<F>)) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }

    /// Creates a new [`GadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[RLWE<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
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
    pub fn basis(&self) -> Basis<F> {
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
    pub fn mul_polynomial(&self, polynomial: &Polynomial<F>) -> RLWE<F> {
        let decomposed = polynomial.decompose(self.basis);
        self.mul_decomposed_polynomial(decomposed)
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// return a [`RLWE<F>`].
    #[inline]
    pub fn mul_decomposed_polynomial(&self, decomposed: Vec<Polynomial<F>>) -> RLWE<F> {
        let mut gadget_rlwe_iter = self.iter();
        let mut decomposed_iter = decomposed.into_iter();

        let init = gadget_rlwe_iter
            .next()
            .unwrap()
            .mul_polynomial(decomposed_iter.next().unwrap());

        gadget_rlwe_iter
            .zip(decomposed_iter)
            .fold(init, |acc, (r, p)| {
                acc.add_element_wise(&r.mul_polynomial(p))
            })
    }

    /// Perform multiplication between [`GadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// then add the `rlwe`, return a [`RLWE<F>`].
    #[inline]
    pub fn mul_decomposed_polynomial_add_rlwe(
        &self,
        decomposed: Vec<Polynomial<F>>,
        rlwe: RLWE<F>,
    ) -> RLWE<F> {
        self.iter().zip(decomposed).fold(rlwe, |acc, (r, p)| {
            acc.add_element_wise(&r.mul_polynomial(p))
        })
    }
}

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different powers
/// of a base, used to control noise growth in polynomial multiplications.
///
/// [`NTTGadgetRLWE`] stores a sequence of [`NTTRLWE`] ciphertexts where each [`NTTRLWE<F>`] instance within
/// the `data` vector represents a ciphertext of a scaled version of a message `m` by successive
/// powers of the `basis`. The first element of `data` is the ciphertext of `m`, the second is `basis * m`,
/// the third is `basis^2 * m`, and so on. This is particularly useful in cryptographic operations
/// where reducing the noise growth during the multiplication of RLWE ciphertexts with polynomials is crucial.
///
/// The struct is generic over a type `F` that must implement the [`NTTField`] trait, which ensures that
/// the field operations are compatible with Number Theoretic Transforms, a key requirement for
/// efficient polynomial operations in RLWE-based cryptography.
#[derive(Debug, Clone)]
pub struct NTTGadgetRLWE<F: NTTField> {
    /// A vector of NTT RLWE ciphertexts, each encrypted message with a different power of the `basis`.
    data: Vec<NTTRLWE<F>>,
    /// The base with respect to which the ciphertexts are scaled.
    basis: Basis<F>,
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

impl<F: NTTField> From<(Vec<NTTRLWE<F>>, Basis<F>)> for NTTGadgetRLWE<F> {
    #[inline]
    fn from((data, basis): (Vec<NTTRLWE<F>>, Basis<F>)) -> Self {
        Self { data, basis }
    }
}

impl<F: NTTField> NTTGadgetRLWE<F> {
    /// Creates a new [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<NTTRLWE<F>>, basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
        Self { data, basis }
    }

    /// Creates a new [`NTTGadgetRLWE<F>`] with reference.
    #[inline]
    pub fn from_ref(data: &[NTTRLWE<F>], basis: Basis<F>) -> Self {
        debug_assert_eq!(data.len(), basis.decompose_len());
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
    pub fn basis(&self) -> Basis<F> {
        self.basis
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetRLWE<F>`].
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, NTTRLWE<F>> {
        self.data.iter()
    }

    /// Returns an iterator over the `data` of this [`NTTGadgetRLWE<F>`]
    /// that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, NTTRLWE<F>> {
        self.data.iter_mut()
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`],
    /// return a [`NTTRLWE<F>`].
    #[inline]
    pub fn mul_polynomial(&self, poly: &Polynomial<F>) -> NTTRLWE<F> {
        let decomposed = poly.decompose(self.basis);
        self.mul_decomposed_polynomial(decomposed)
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// return a [`NTTRLWE<F>`].
    #[inline]
    pub fn mul_decomposed_polynomial(&self, decomposed: Vec<Polynomial<F>>) -> NTTRLWE<F> {
        let mut gadget_rlwe_iter = self.iter();
        let mut decomposed_iter = decomposed.into_iter();

        let init = gadget_rlwe_iter
            .next()
            .unwrap()
            .mul_polynomial(decomposed_iter.next().unwrap());

        gadget_rlwe_iter
            .zip(decomposed_iter)
            .fold(init, |acc, (g, d)| acc.add_rlwe_mul_polynomial(g, d))
    }

    /// Perform multiplication between [`NTTGadgetRLWE<F>`] and [`Polynomial<F>`] slice,
    /// then add the `rlwe`, return a [`NTTRLWE<F>`].
    #[inline]
    pub fn mul_decomposed_polynomial_add_rlwe(
        &self,
        decomposed: Vec<Polynomial<F>>,
        rlwe: NTTRLWE<F>,
    ) -> NTTRLWE<F> {
        self.iter()
            .zip(decomposed)
            .fold(rlwe, |acc, (gadget, decomposed_polynomial)| {
                acc.add_rlwe_mul_polynomial(gadget, decomposed_polynomial)
            })
    }
}

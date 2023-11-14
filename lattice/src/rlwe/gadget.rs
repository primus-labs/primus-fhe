use std::ops::Mul;

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Poly, Polynomial},
};

use crate::RLWE;

/// A special RLWE type, which stores a message with different basis.
#[derive(Clone)]
pub struct GadgetRLWE<F: NTTField> {
    data: Vec<RLWE<F>>,
    basis: F::Modulus,
}

impl<F: NTTField> IntoIterator for GadgetRLWE<F> {
    type Item = RLWE<F>;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<F: NTTField> GadgetRLWE<F> {
    /// Creates a new [`GadgetRLWE<F>`].
    #[inline]
    pub fn new(data: Vec<RLWE<F>>, basis: F::Modulus) -> Self {
        Self { data, basis }
    }

    /// Returns a reference to the data of this [`GadgetRLWE<F>`].
    #[inline]
    pub fn data(&self) -> &[RLWE<F>] {
        self.data.as_ref()
    }

    /// Returns an iterator over the slice.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, RLWE<F>> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, RLWE<F>> {
        self.data.iter_mut()
    }

    /// Returns a reference to the basis of this [`GadgetRLWE<F>`].
    pub fn basis(&self) -> &F::Modulus {
        &self.basis
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for GadgetRLWE<F> {
    type Output = RLWE<F>;

    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        let n = rhs.coeff_count();

        let inti_zero = RLWE::zero(n);
        let decompose = rhs.decompose(self.basis);
        self.data
            .into_iter()
            .zip(decompose)
            .fold(inti_zero, |acc, (l, r)| acc + l * r)
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for GadgetRLWE<F> {
    type Output = RLWE<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        let n = rhs.coeff_count();

        let inti_zero = RLWE::zero(n);
        let decompose = rhs.decompose(self.basis);
        self.data
            .into_iter()
            .zip(decompose)
            .fold(inti_zero, |acc, (l, r)| acc + l * r)
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &GadgetRLWE<F> {
    type Output = RLWE<F>;

    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        let n = rhs.coeff_count();

        let inti_zero = RLWE::zero(n);
        let decompose = rhs.decompose(self.basis.clone());
        self.data
            .iter()
            .zip(decompose)
            .fold(inti_zero, |acc, (l, r)| acc + l.clone() * r)
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &GadgetRLWE<F> {
    type Output = RLWE<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        let n = rhs.coeff_count();

        let inti_zero = RLWE::zero(n);
        let decompose = rhs.decompose(self.basis.clone());
        self.data
            .iter()
            .zip(decompose)
            .fold(inti_zero, |acc, (l, r)| acc + l.clone() * r)
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for GadgetRLWE<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self, <Polynomial<F>>::from(rhs))
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for GadgetRLWE<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self, <Polynomial<F>>::from(rhs))
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for &GadgetRLWE<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self, <Polynomial<F>>::from(rhs))
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for &GadgetRLWE<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self, <Polynomial<F>>::from(rhs))
    }
}

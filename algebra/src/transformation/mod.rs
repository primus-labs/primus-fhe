//! This module mainly defines and implements
//! the functions, structures and methods of number theory transform.
//!
//! Using this module, you can speed up multiplication
//! of polynomials, large integers, and so on.

#[cfg(feature = "concrete-ntt")]
mod concrete;
mod ntt_table;

#[cfg(feature = "concrete-ntt")]
pub use concrete::{prime32, prime64};
#[cfg(feature = "count_ntt")]
pub use ntt_table::count;
pub use ntt_table::NTTTable;

use crate::{NTTField, NTTPolynomial, Polynomial};

/// An abstract layer for ntt table
pub trait AbstractNTT<F: NTTField> {
    /// Get the root for number theory transform.
    fn root(&self) -> F;

    /// Perform a fast number theory transform.
    ///
    /// This function transforms a [`Polynomial<F>`] to a [`NTTPolynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `polynomial` - inputs in normal order, outputs in bit-reversed order
    #[inline]
    fn transform(&self, polynomial: &Polynomial<F>) -> NTTPolynomial<F> {
        self.transform_inplace(polynomial.clone())
    }

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a [`Polynomial<F>`] to a [`NTTPolynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `polynomial` - inputs in normal order, outputs in bit-reversed order
    #[inline]
    fn transform_inplace(&self, mut polynomial: Polynomial<F>) -> NTTPolynomial<F> {
        self.transform_slice(polynomial.as_mut_slice());
        NTTPolynomial::<F>::new(polynomial.data())
    }

    /// Perform a fast inverse number theory transform.
    ///
    /// This function transforms a [`NTTPolynomial<F>`] to a [`Polynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `ntt_polynomial` - inputs in bit-reversed order, outputs in normal order
    #[inline]
    fn inverse_transform(&self, ntt_polynomial: &NTTPolynomial<F>) -> Polynomial<F> {
        self.inverse_transform_inplace(ntt_polynomial.clone())
    }

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a [`NTTPolynomial<F>`] to a [`Polynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `ntt_polynomial` - inputs in bit-reversed order, outputs in normal order
    #[inline]
    fn inverse_transform_inplace(&self, mut ntt_polynomial: NTTPolynomial<F>) -> Polynomial<F> {
        self.inverse_transform_slice(ntt_polynomial.as_mut_slice());
        Polynomial::<F>::new(ntt_polynomial.data())
    }

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a [`Polynomial<F>`] slice with coefficient in `[0, 4*modulus)`
    /// to a [`NTTPolynomial<F>`] slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `polynomial_slice` - inputs in normal order, outputs in bit-reversed order
    fn transform_slice(&self, polynomial_slice: &mut [F]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a [`NTTPolynomial<F>`] slice with coefficient in `[0, 2*modulus)`
    /// to a [`Polynomial<F>`] slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `ntt_polynomial_slice` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]);
}

/// Number theory transform for monomial.
pub trait MonomialNTT<F: NTTField> {
    /// Perform a fast number theory transform for **monomial** `coeff*X^degree` in place.
    fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]);

    /// Perform a fast number theory transform for **monomial** `X^degree` in place.
    #[inline]
    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
        self.transform_monomial(F::one(), degree, values);
    }

    /// Perform a fast number theory transform for **monomial** `-X^degree` in place.
    #[inline]
    fn transform_coeff_neg_one_monomial(&self, degree: usize, values: &mut [F]) {
        self.transform_monomial(F::neg_one(), degree, values);
    }
}

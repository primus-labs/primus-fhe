//! This module mainly defines and implements
//! the functions, structures and methods of number theory transform.
//!
//! Using this module, you can speed up multiplication
//! of polynomials, large integers, and so on.

mod ntt_table;

pub use ntt_table::NTTTable;

use crate::{NTTField, NTTPolynomial, Polynomial};

/// An abstract layer for ntt table
pub trait AbstractNTT<F: NTTField> {
    /// Perform a fast number theory transform.
    ///
    /// This function transforms a [`Polynomial<F>`] to a [`NTTPolynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `polynomial` - inputs in normal order, outputs in bit-reversed order
    fn transform(&self, polynomial: &Polynomial<F>) -> NTTPolynomial<F>;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a [`Polynomial<F>`] to a [`NTTPolynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `polynomial` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace(&self, polynomial: Polynomial<F>) -> NTTPolynomial<F>;

    /// Perform a fast inverse number theory transform.
    ///
    /// This function transforms a [`NTTPolynomial<F>`] to a [`Polynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `ntt_polynomial` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform(&self, ntt_polynomial: &NTTPolynomial<F>) -> Polynomial<F>;

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a [`NTTPolynomial<F>`] to a [`Polynomial<F>`].
    ///
    /// # Arguments
    ///
    /// * `ntt_polynomial` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace(&self, ntt_polynomial: NTTPolynomial<F>) -> Polynomial<F>;

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
    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]);
}

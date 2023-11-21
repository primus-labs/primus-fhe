//! This module mainly defines and implements
//! the functions, structures and methods
//! of number theory transform.
//!
//! Using this module, you can speed up multiplication
//! of polynomials, large integers, and so on.

mod ntt_table;

pub use ntt_table::NTTTable;

use crate::field::NTTField;
use crate::polynomial::{NTTPolynomial, Polynomial};

/// An abstract layer for ntt table
pub trait AbstractNTT<F: NTTField> {
    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial to a vector.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace(&self, poly: Polynomial<F>) -> NTTPolynomial<F>;

    /// Perform a fast number theory transform.
    ///
    /// This function transforms a polynomial to a vector.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform(&self, poly: &Polynomial<F>) -> NTTPolynomial<F>;

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a vector to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace(&self, vec: NTTPolynomial<F>) -> Polynomial<F>;

    /// Perform a fast inverse number theory transform.
    ///
    /// This function transforms a vector to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform(&self, vec: &NTTPolynomial<F>) -> Polynomial<F>;
}

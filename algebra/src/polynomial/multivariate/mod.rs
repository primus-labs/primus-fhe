pub mod data_structures;
pub mod multilinear;

use std::fmt::Debug;

use crate::field::Field;

/// Describes the common interface for univariate and multivariate polynomials
pub trait PolynomialTrait<F: Field>: Sized + Clone + Debug {
    /// The type of evaluation points for this polynomial.
    type Point: Sized + Clone + Debug;

    /// Returns the total degree of the polynomial
    fn degree(&self) -> usize;

    /// Evaluates `self` at the given `point` in `Self::Point`.
    fn evaluate(&self, point: &Self::Point) -> F;
}

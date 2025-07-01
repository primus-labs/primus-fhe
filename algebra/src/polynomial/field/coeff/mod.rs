use num_traits::{ConstZero, Zero};
use serde::{Deserialize, Serialize};

use crate::{reduce::ReduceMulAdd, Field};

mod basic;
mod convert;
mod decompose;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Represents a polynomial where coefficients are numeric elements.
#[derive(Serialize, Deserialize)]
#[serde(bound = "F: Field")]
pub struct FieldPolynomial<F: Field> {
    data: Vec<<F as Field>::ValueT>,
}

impl<F: Field> Default for FieldPolynomial<F> {
    #[inline]
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<F: Field> core::fmt::Debug for FieldPolynomial<F> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FieldPolynomial")
            .field("data", &self.data)
            .finish()
    }
}

impl<F: Field> Eq for FieldPolynomial<F> {}

impl<F: Field> PartialEq for FieldPolynomial<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<F: Field> Clone for FieldPolynomial<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<F: Field> FieldPolynomial<F> {
    /// Creates a new [`FieldPolynomial<F>`].
    #[inline]
    pub fn new(poly: Vec<<F as Field>::ValueT>) -> Self {
        Self { data: poly }
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_data(self) -> Vec<<F as Field>::ValueT> {
        self.data
    }

    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[<F as Field>::ValueT]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[<F as Field>::ValueT] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.data.as_mut_slice()
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, <F as Field>::ValueT> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, <F as Field>::ValueT> {
        self.data.iter_mut()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, <F as Field>::ValueT>> {
        self.data.iter().copied()
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> <F as Field>::ValueT,
    {
        self.data.resize_with(new_degree, f);
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: <F as Field>::ValueT) {
        self.data.resize(new_degree, value);
    }

    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[<F as Field>::ValueT]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Creates a [`FieldPolynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![<F as Field>::ValueT::ZERO; coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.data.is_empty()
            || self
                .data
                .iter()
                .all(<<F as Field>::ValueT as Zero>::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.fill(<F as Field>::ValueT::ZERO);
    }

    /// Evaluate p(x).
    #[inline]
    pub fn evaluate(&self, x: <F as Field>::ValueT) -> <F as Field>::ValueT {
        self.data
            .iter()
            .rev()
            .fold(<F as Field>::ValueT::ZERO, |acc, &a| {
                F::MODULUS.reduce_mul_add(acc, x, a)
            })
    }
}

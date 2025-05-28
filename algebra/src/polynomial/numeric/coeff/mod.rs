use num_traits::{ConstZero, Zero};
use serde::{Deserialize, Serialize};

use crate::reduce::ReduceMulAdd;

mod basic;
mod convert;
mod decompose;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Represents a polynomial where coefficients are elements of a specified numeric `T`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Polynomial<T> {
    poly: Vec<T>,
}

impl<T> Default for Polynomial<T> {
    #[inline]
    fn default() -> Self {
        Self { poly: Vec::new() }
    }
}

impl<T> Polynomial<T> {
    /// Creates a new [`Polynomial<T>`].
    #[inline]
    pub fn new(poly: Vec<T>) -> Self {
        Self { poly }
    }

    /// Drop self, and return the vector.
    #[inline]
    pub fn inner_vec(self) -> Vec<T> {
        self.poly
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.poly.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.poly.as_mut_slice()
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.poly.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<T> {
        self.poly.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<T> {
        self.poly.iter_mut()
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_coeff_count: usize, f: FN)
    where
        FN: FnMut() -> T,
    {
        self.poly.resize_with(new_coeff_count, f);
    }
}

impl<T: Clone> Polynomial<T> {
    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_coeff_count: usize, value: T) {
        self.poly.resize(new_coeff_count, value);
    }
}

impl<T: Copy> Polynomial<T> {
    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[T]>) {
        self.poly.copy_from_slice(src.as_ref())
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, T>> {
        self.poly.iter().copied()
    }
}

impl<T> Polynomial<T>
where
    T: Copy + ConstZero,
{
    /// Creates a [`Polynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            poly: vec![<T as ConstZero>::ZERO; coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.poly.is_empty() || self.poly.iter().all(<T as Zero>::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.poly.fill(<T as ConstZero>::ZERO);
    }

    /// Evaluate p(x).
    #[inline]
    pub fn evaluate<Modulus>(&self, x: T, modulus: Modulus) -> T
    where
        Modulus: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.poly
            .iter()
            .rev()
            .fold(<T as ConstZero>::ZERO, |acc, &a| {
                modulus.reduce_mul_add(acc, x, a)
            })
    }
}

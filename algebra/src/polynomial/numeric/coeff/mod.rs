use num_traits::ConstZero;

use crate::reduce::ReduceMulAdd;

mod basic;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Represents a polynomial where coefficients are elements of a specified numeric `T`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NumPolynomial<T> {
    data: Vec<T>,
}

impl<T> NumPolynomial<T> {
    /// Creates a new [`NumPolynomial<T>`].
    #[inline]
    pub fn new(poly: Vec<T>) -> Self {
        Self { data: poly }
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_data(self) -> Vec<T> {
        self.data
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.data.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.data.as_mut_slice()
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<T> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<T> {
        self.data.iter_mut()
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> T,
    {
        self.data.resize_with(new_degree, f);
    }
}

impl<T: Clone> NumPolynomial<T> {
    /// Constructs a new polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: T) {
        self.data.resize(new_degree, value);
    }
}

impl<T: Copy> NumPolynomial<T> {
    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[T]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> std::iter::Copied<std::slice::Iter<'_, T>> {
        self.data.iter().copied()
    }
}

impl<T> NumPolynomial<T>
where
    T: Copy + ConstZero,
{
    /// Creates a [`NumPolynomial<F>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![T::ZERO; coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.data.is_empty() || self.data.iter().all(T::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.data.fill(T::ZERO);
    }

    /// Evaluate p(x).
    #[inline]
    pub fn evaluate<M>(&self, x: T, modulus: M) -> T
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.data
            .iter()
            .rev()
            .fold(T::ZERO, |acc, &a| modulus.reduce_mul_add(acc, x, a))
    }
}

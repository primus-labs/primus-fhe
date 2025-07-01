use num_traits::{ConstZero, Zero};

use crate::{
    numeric::Numeric,
    reduce::{LazyReduceMulAdd, ReduceMulAdd},
};

mod basic;
mod convert;
mod random;

mod add;
mod inv;
mod mul;
mod neg;
mod sub;

/// Represents a ntt polynomial where values are elements of a specified numeric `T`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NttPolynomial<T> {
    values: Vec<T>,
}

impl<T> Default for NttPolynomial<T> {
    #[inline]
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

impl<T> NttPolynomial<T> {
    /// Creates a new [`NttPolynomial<T>`].
    #[inline]
    pub fn new(values: Vec<T>) -> Self {
        Self { values }
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_vec(self) -> Vec<T> {
        self.values
    }

    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.values.as_slice()
    }

    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.values.as_mut_slice()
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.values.len()
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.values.iter()
    }

    /// Returns an iterator that allows modifying each value or coefficient of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.values.iter_mut()
    }

    /// Resize the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_value_count: usize, f: FN)
    where
        FN: FnMut() -> T,
    {
        self.values.resize_with(new_value_count, f);
    }
}

impl<T: Clone> NttPolynomial<T> {
    /// Constructs a new ntt polynomial from a slice.
    #[inline]
    pub fn from_slice(polynomial: &[T]) -> Self {
        Self::new(polynomial.to_vec())
    }

    /// Resize the coefficient count of the ntt polynomial.
    #[inline]
    pub fn resize(&mut self, new_value_count: usize, value: T) {
        self.values.resize(new_value_count, value);
    }
}

impl<T: Copy> NttPolynomial<T> {
    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[T]>) {
        self.values.copy_from_slice(src.as_ref())
    }

    /// Returns an iterator that allows reading each value or coefficient of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, T>> {
        self.values.iter().copied()
    }
}

impl<T> NttPolynomial<T>
where
    T: Copy + ConstZero,
{
    /// Creates a [`NttPolynomial<T>`] with all coefficients equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            values: vec![<T as ConstZero>::ZERO; coeff_count],
        }
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.values.is_empty() || self.values.iter().all(<T as Zero>::is_zero)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.values.fill(<T as ConstZero>::ZERO);
    }
}

impl<T: Numeric> NttPolynomial<T> {
    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign<M>(&mut self, a: &Self, b: &Self, modulus: M)
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.into_iter()
            .zip(a)
            .zip(b)
            .for_each(|((z, &x), &y)| *z = modulus.reduce_mul_add(x, y, *z));
    }

    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign_fast<M>(&mut self, a: &Self, b: &Self, modulus: M)
    where
        M: Copy + LazyReduceMulAdd<T, Output = T>,
    {
        self.into_iter()
            .zip(a)
            .zip(b)
            .for_each(|((z, &x), &y)| *z = modulus.lazy_reduce_mul_add(x, y, *z));
    }

    /// Performs `des = self * b + c`.
    #[inline]
    pub fn mul_add_inplace<M>(&self, b: &Self, c: &Self, des: &mut Self, modulus: M)
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        des.into_iter()
            .zip(self)
            .zip(b)
            .zip(c)
            .for_each(|(((d, &a), &b), &c)| *d = modulus.reduce_mul_add(a, b, c));
    }

    /// Performs `des = self * b + c`.
    #[inline]
    pub fn mul_add_inplace_fast<M>(&self, b: &Self, c: &Self, des: &mut Self, modulus: M)
    where
        M: Copy + LazyReduceMulAdd<T, Output = T>,
    {
        des.into_iter()
            .zip(self)
            .zip(b)
            .zip(c)
            .for_each(|(((d, &a), &b), &c)| *d = modulus.lazy_reduce_mul_add(a, b, c));
    }
}

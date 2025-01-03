use num_traits::{ConstZero, Zero};

use crate::{
    reduce::{LazyReduceMulAdd, ReduceMulAdd},
    Field, NttField,
};

mod basic;
mod convert;
mod random;

mod add;
mod inv;
mod mul;
mod neg;
mod sub;

/// A representation of a polynomial in Number Theoretic Transform (NTT) form.
pub struct FieldNttPolynomial<F: NttField> {
    data: Vec<<F as Field>::ValueT>,
}

impl<F: NttField> Default for FieldNttPolynomial<F> {
    #[inline]
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<F: NttField> core::fmt::Debug for FieldNttPolynomial<F> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FieldNttPolynomial")
            .field("data", &self.data)
            .finish()
    }
}

impl<F: NttField> Eq for FieldNttPolynomial<F> {}

impl<F: NttField> PartialEq for FieldNttPolynomial<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<F: NttField> Clone for FieldNttPolynomial<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<F: NttField> FieldNttPolynomial<F> {
    /// Creates a new [`FieldNttPolynomial<F>`].
    #[inline]
    pub fn new(data: Vec<<F as Field>::ValueT>) -> Self {
        Self { data }
    }

    /// Drop self, and return the data.
    #[inline]
    pub fn inner_data(self) -> Vec<<F as Field>::ValueT> {
        self.data
    }

    /// Constructs a ntt polynomial from a slice.
    #[inline]
    pub fn from_slice(vec: &[<F as Field>::ValueT]) -> Self {
        Self::new(vec.to_vec())
    }

    /// Copy the values from another slice.
    #[inline]
    pub fn copy_from(&mut self, src: impl AsRef<[<F as Field>::ValueT]>) {
        self.data.copy_from_slice(src.as_ref())
    }

    /// Get the coefficient counts of polynomial.
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.data.len()
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

    /// Returns an iterator that allows reading each value or values of the polynomial.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<<F as Field>::ValueT> {
        self.data.iter()
    }

    /// Returns an iterator that allows modifying each value or values of the polynomial.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<<F as Field>::ValueT> {
        self.data.iter_mut()
    }

    /// Returns an iterator that allows reading each value or values of the polynomial.
    #[inline]
    pub fn copied_iter(&self) -> core::iter::Copied<core::slice::Iter<'_, <F as Field>::ValueT>> {
        self.data.iter().copied()
    }

    /// Alter the coefficient count of the polynomial.
    #[inline]
    pub fn resize_with<FN>(&mut self, new_degree: usize, f: FN)
    where
        FN: FnMut() -> <F as Field>::ValueT,
    {
        self.data.resize_with(new_degree, f);
    }

    /// Alter the coefficient count of the polynomial.
    #[inline]
    pub fn resize(&mut self, new_degree: usize, value: <F as Field>::ValueT) {
        self.data.resize(new_degree, value);
    }

    /// Creates a [`FieldNttPolynomial<F>`] with all values equal to zero.
    #[inline]
    pub fn zero(coeff_count: usize) -> Self {
        Self {
            data: vec![<<F as Field>::ValueT as ConstZero>::ZERO; coeff_count],
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
        self.data.fill(<<F as Field>::ValueT as ConstZero>::ZERO);
    }

    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign(&mut self, a: &Self, b: &Self) {
        self.into_iter()
            .zip(a)
            .zip(b)
            .for_each(|((z, &x), &y)| *z = F::MODULUS.reduce_mul_add(x, y, *z));
    }

    /// Performs `self = self - (a * b)`.
    #[inline]
    pub fn sub_mul_assign(&mut self, a: &Self, b: &Self) {
        self.into_iter()
            .zip(a)
            .zip(b)
            .for_each(|((z, &x), &y)| *z = F::MODULUS.reduce_mul_add(x, y, F::MODULUS_VALUE - *z));
    }

    /// Performs `self = self + (a * b)`.
    #[inline]
    pub fn add_mul_assign_fast(&mut self, a: &Self, b: &Self) {
        self.into_iter()
            .zip(a)
            .zip(b)
            .for_each(|((z, &x), &y)| *z = F::MODULUS.lazy_reduce_mul_add(x, y, *z));
    }

    /// Performs `self = self - (a * b)`.
    #[inline]
    pub fn sub_mul_assign_fast(&mut self, a: &Self, b: &Self) {
        self.into_iter().zip(a).zip(b).for_each(|((z, &x), &y)| {
            *z = F::MODULUS.lazy_reduce_mul_add(x, y, F::MODULUS_VALUE - *z)
        });
    }

    /// Performs `des = self * b + c`.
    #[inline]
    pub fn mul_add_inplace(&self, b: &Self, c: &Self, des: &mut Self) {
        des.into_iter()
            .zip(self)
            .zip(b)
            .zip(c)
            .for_each(|(((d, &a), &b), &c)| *d = F::MODULUS.reduce_mul_add(a, b, c));
    }

    /// Performs `des = self * b + c`.
    #[inline]
    pub fn mul_add_inplace_fast(&self, b: &Self, c: &Self, des: &mut Self) {
        des.into_iter()
            .zip(self)
            .zip(b)
            .zip(c)
            .for_each(|(((d, &a), &b), &c)| *d = F::MODULUS.lazy_reduce_mul_add(a, b, c));
    }
}

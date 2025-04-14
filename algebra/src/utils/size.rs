use core::mem;

use crate::{
    integer::{Integer, UnsignedInteger},
    polynomial::{FieldNttPolynomial, FieldPolynomial, NttPolynomial, Polynomial},
    Field, NttField,
};

/// A trait for the size of a value.
pub trait Size {
    /// Returns the size of the pointed-to value in bytes.
    fn size(&self) -> usize;
}

impl<T: Integer> Size for Vec<T> {
    #[inline]
    fn size(&self) -> usize {
        self.len() * mem::size_of::<T>()
    }
}

impl<F: Field> Size for FieldPolynomial<F> {
    #[inline]
    fn size(&self) -> usize {
        self.coeff_count() * mem::size_of::<F::ValueT>()
    }
}

impl<F: NttField> Size for FieldNttPolynomial<F> {
    #[inline]
    fn size(&self) -> usize {
        self.coeff_count() * mem::size_of::<F::ValueT>()
    }
}

impl<T: UnsignedInteger> Size for Polynomial<T> {
    #[inline]
    fn size(&self) -> usize {
        self.coeff_count() * mem::size_of::<T>()
    }
}

impl<T: UnsignedInteger> Size for NttPolynomial<T> {
    #[inline]
    fn size(&self) -> usize {
        self.coeff_count() * mem::size_of::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size() {
        let a = vec![1u32, 2, 3];
        assert_eq!(a.size(), 12);
    }
}

use core::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use super::NttPolynomial;

impl<T, I: SliceIndex<[T]>> IndexMut<I> for NttPolynomial<T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.values, index)
    }
}

impl<T, I: SliceIndex<[T]>> Index<I> for NttPolynomial<T> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.values, index)
    }
}

impl<T> AsRef<[T]> for NttPolynomial<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.values.as_ref()
    }
}

impl<T> AsMut<[T]> for NttPolynomial<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.values.as_mut()
    }
}

impl<T> IntoIterator for NttPolynomial<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NttPolynomial<T> {
    type Item = &'a T;

    type IntoIter = core::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut NttPolynomial<T> {
    type Item = &'a mut T;

    type IntoIter = core::slice::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

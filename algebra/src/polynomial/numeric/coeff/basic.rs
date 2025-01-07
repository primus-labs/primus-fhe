use core::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use super::Polynomial;

impl<T, I: SliceIndex<[T]>> IndexMut<I> for Polynomial<T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.poly, index)
    }
}

impl<T, I: SliceIndex<[T]>> Index<I> for Polynomial<T> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.poly, index)
    }
}

impl<T> AsRef<[T]> for Polynomial<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.poly.as_ref()
    }
}

impl<T> AsMut<[T]> for Polynomial<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.poly.as_mut()
    }
}

impl<T> IntoIterator for Polynomial<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.poly.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Polynomial<T> {
    type Item = &'a T;

    type IntoIter = core::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.poly.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Polynomial<T> {
    type Item = &'a mut T;

    type IntoIter = core::slice::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.poly.iter_mut()
    }
}

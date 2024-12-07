use std::{
    ops::{Index, IndexMut},
    slice::{Iter, IterMut, SliceIndex},
    vec::IntoIter,
};

use super::Polynomial;

impl<F, I: SliceIndex<[F]>> IndexMut<I> for Polynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F, I: SliceIndex<[F]>> Index<I> for Polynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: Copy> AsRef<Self> for Polynomial<F> {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F: Copy> AsRef<[F]> for Polynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[F] {
        self.data.as_ref()
    }
}

impl<F: Copy> AsMut<[F]> for Polynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [F] {
        self.data.as_mut()
    }
}

impl<F> IntoIterator for Polynomial<F> {
    type Item = F;

    type IntoIter = IntoIter<F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F> IntoIterator for &'a Polynomial<F> {
    type Item = &'a F;

    type IntoIter = Iter<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F> IntoIterator for &'a mut Polynomial<F> {
    type Item = &'a mut F;

    type IntoIter = IterMut<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

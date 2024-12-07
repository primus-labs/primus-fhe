use std::{
    ops::{Index, IndexMut},
    slice::{Iter, IterMut, SliceIndex},
    vec::IntoIter,
};

use super::NTTPolynomial;

impl<F, I: SliceIndex<[F]>> IndexMut<I> for NTTPolynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F, I: SliceIndex<[F]>> Index<I> for NTTPolynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F> AsRef<Self> for NTTPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F> AsRef<[F]> for NTTPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[F] {
        self.data.as_ref()
    }
}

impl<F> AsMut<[F]> for NTTPolynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [F] {
        self.data.as_mut()
    }
}

impl<F> IntoIterator for NTTPolynomial<F> {
    type Item = F;

    type IntoIter = IntoIter<F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F> IntoIterator for &'a NTTPolynomial<F> {
    type Item = &'a F;

    type IntoIter = Iter<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F> IntoIterator for &'a mut NTTPolynomial<F> {
    type Item = &'a mut F;

    type IntoIter = IterMut<'a, F>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

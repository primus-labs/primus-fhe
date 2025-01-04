use core::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use crate::Field;

use super::FieldPolynomial;

impl<F: Field, I: SliceIndex<[<F as Field>::ValueT]>> IndexMut<I> for FieldPolynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: Field, I: SliceIndex<[<F as Field>::ValueT]>> Index<I> for FieldPolynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: Field> AsRef<[<F as Field>::ValueT]> for FieldPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[<F as Field>::ValueT] {
        self.data.as_ref()
    }
}

impl<F: Field> AsMut<[<F as Field>::ValueT]> for FieldPolynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [<F as Field>::ValueT] {
        self.data.as_mut()
    }
}

impl<F: Field> IntoIterator for FieldPolynomial<F> {
    type Item = <F as Field>::ValueT;

    type IntoIter = std::vec::IntoIter<<F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a FieldPolynomial<F> {
    type Item = &'a <F as Field>::ValueT;

    type IntoIter = core::slice::Iter<'a, <F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F: Field> IntoIterator for &'a mut FieldPolynomial<F> {
    type Item = &'a mut <F as Field>::ValueT;

    type IntoIter = core::slice::IterMut<'a, <F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

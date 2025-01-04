use core::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use crate::{Field, NttField};

use super::FieldNttPolynomial;

impl<F: NttField, I: SliceIndex<[<F as Field>::ValueT]>> IndexMut<I> for FieldNttPolynomial<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: NttField, I: SliceIndex<[<F as Field>::ValueT]>> Index<I> for FieldNttPolynomial<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: NttField> AsRef<[<F as Field>::ValueT]> for FieldNttPolynomial<F> {
    #[inline]
    fn as_ref(&self) -> &[<F as Field>::ValueT] {
        self.data.as_ref()
    }
}

impl<F: NttField> AsMut<[<F as Field>::ValueT]> for FieldNttPolynomial<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [<F as Field>::ValueT] {
        self.data.as_mut()
    }
}

impl<F: NttField> IntoIterator for FieldNttPolynomial<F> {
    type Item = <F as Field>::ValueT;

    type IntoIter = std::vec::IntoIter<<F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, F: NttField> IntoIterator for &'a FieldNttPolynomial<F> {
    type Item = &'a <F as Field>::ValueT;

    type IntoIter = core::slice::Iter<'a, <F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<'a, F: NttField> IntoIterator for &'a mut FieldNttPolynomial<F> {
    type Item = &'a mut <F as Field>::ValueT;

    type IntoIter = core::slice::IterMut<'a, <F as Field>::ValueT>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

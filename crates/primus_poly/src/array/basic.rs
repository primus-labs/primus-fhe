use core::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use num_traits::{ConstZero, Zero};
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};

use super::ArrayBase;

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Returns an iterator that allows reading each value.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Returns `true` if all elements are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(<T as Zero>::is_zero)
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Returns an iterator that allows modifying each value.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Sets all elements to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(<T as ConstZero>::ZERO);
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a new [`ArrayBase`] with all elements equal to zero.
    #[inline]
    pub fn zero(len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; len]))
    }
}

impl<S, T> Size for ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}

impl<S, T, I: SliceIndex<[T]>> Index<I> for ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(self.0.as_slice(), index)
    }
}

impl<S, T, I: SliceIndex<[T]>> IndexMut<I> for ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(self.0.as_mut_slice(), index)
    }
}

impl<S, T> AsRef<[T]> for ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.0.as_slice()
    }
}

impl<S, T> AsMut<[T]> for ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }
}

impl<'t, S, T> IntoIterator for &'t ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    type Item = &'t T;

    type IntoIter = core::slice::Iter<'t, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'t, S, T> IntoIterator for &'t mut ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    type Item = &'t mut T;

    type IntoIter = core::slice::IterMut<'t, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<S, T> IntoIterator for ArrayBase<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    type Item = T;

    type IntoIter = S::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        <S as DataOwned>::into_iter(self.0)
    }
}

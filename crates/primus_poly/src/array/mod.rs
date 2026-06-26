use std::ops::{Deref, DerefMut};

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

mod basic;
mod random;

mod add;
mod mul;
mod neg;
mod sub;

/// Owned [`ArrayBase`] backed by a [`Vec`].
pub type Array<T> = ArrayBase<Vec<T>>;

/// Borrowed [`ArrayBase`] backed by an immutable slice.
pub type ArrayRef<'a, T> = ArrayBase<&'a [T]>;

/// Mutably borrowed [`ArrayBase`] backed by a mutable slice.
pub type ArrayMut<'a, T> = ArrayBase<&'a mut [T]>;

/// A flat array of FHE values. Supports element-wise arithmetic with modular reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayBase<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl<S> ArrayBase<S>
where
    S: RawData,
    <S as RawData>::Elem: FheUint,
{
    /// Creates a new [`ArrayBase<S>`].
    #[inline]
    pub fn new(data: S) -> Self {
        Self(data)
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Constructs a new array from a slice.
    #[inline]
    pub fn from_slice(data: &[T]) -> Self {
        Self(S::from_slice(data))
    }

    /// Constructs a new array from a vector.
    #[inline(always)]
    pub fn from_vec(data: Vec<T>) -> Self {
        Self(S::from_vec(data))
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Copies elements from a slice into `self`.
    #[inline]
    pub fn copy_from_slice(&mut self, src: &[T]) {
        self.0.copy_from_slice(src);
    }

    /// Returns a mutable iterator over `chunk_size` elements at a time.
    #[inline]
    pub fn chunks_exact_mut(&mut self, chunk_size: usize) -> std::slice::ChunksExactMut<'_, T> {
        DataMut::chunks_exact_mut(&mut self.0, chunk_size)
    }
}
impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Returns the number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if `self` has a length of 0.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over `chunk_size` elements at a time.
    #[inline]
    pub fn chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, T> {
        Data::chunks_exact(&self.0, chunk_size)
    }
}

impl<S, T> FromIterator<T> for ArrayBase<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    #[inline]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(<S as FromIterator<T>>::from_iter(iter))
    }
}

impl<S, T> Deref for ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    type Target = S;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> DerefMut for ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

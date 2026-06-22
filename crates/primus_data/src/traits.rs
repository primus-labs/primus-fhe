use std::slice::{Iter, IterMut};

/// Sealed marker at the root of the storage trait hierarchy.
///
/// Every storage backend exposes its element type via [`Elem`](RawData::Elem).
/// Concrete capabilities — read access, mutation, and ownership — are added by
/// [`Data`], [`DataMut`], and [`DataOwned`] respectively.
pub trait RawData: Sized {
    /// The element type stored in this buffer.
    type Elem;
}

/// Read-only access to a contiguous buffer of [`RawData::Elem`].
///
/// Backends only need to provide [`as_slice`](Data::as_slice); all other
/// methods have default implementations that delegate to `<[T]>::*` via
/// `as_slice()`.
pub trait Data: RawData {
    /// Returns the entire contents as a slice.
    fn as_slice(&self) -> &[Self::Elem];

    /// Returns the number of elements.
    #[inline(always)]
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns `true` if the buffer has length 0.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Returns an iterator over the elements.
    #[inline(always)]
    fn iter(&self) -> Iter<'_, Self::Elem> {
        self.as_slice().iter()
    }

    /// Returns an iterator over `chunk_size` elements at a time.
    ///
    /// Chunks are non-overlapping slices of exactly `chunk_size` elements.
    /// Trailing elements that do not fill a complete chunk are omitted and
    /// can be retrieved via the iterator's `remainder` method.
    ///
    /// # Panics
    /// Panics if `chunk_size` is zero.
    #[inline(always)]
    fn chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, Self::Elem> {
        self.as_slice().chunks_exact(chunk_size)
    }

    /// Divides the buffer into two slices at `mid`.
    ///
    /// # Panics
    /// Panics if `mid > self.len()`.
    #[inline(always)]
    fn split_at(&self, mid: usize) -> (&[Self::Elem], &[Self::Elem]) {
        self.as_slice().split_at(mid)
    }

    /// Divides the buffer into two slices at `mid`, without bounds checking.
    ///
    /// # Safety
    /// The caller must ensure `0 <= mid <= self.len()`.
    #[inline(always)]
    unsafe fn split_at_unchecked(&self, mid: usize) -> (&[Self::Elem], &[Self::Elem]) {
        unsafe { self.as_slice().split_at_unchecked(mid) }
    }

    /// Returns the first element, or `None` if empty.
    #[inline(always)]
    fn first(&self) -> Option<&Self::Elem> {
        self.as_slice().first()
    }

    /// Returns the last element, or `None` if empty.
    #[inline(always)]
    fn last(&self) -> Option<&Self::Elem> {
        self.as_slice().last()
    }

    /// Splits the buffer into a prefix of `N`-element chunks and a remainder.
    ///
    /// The remainder has fewer than `N` elements.
    #[inline(always)]
    fn as_chunks<const N: usize>(&self) -> (&[[Self::Elem; N]], &[Self::Elem]) {
        self.as_slice().as_chunks()
    }
}

/// Mutable access to a contiguous buffer of [`RawData::Elem`].
///
/// Backends only need to provide [`as_mut_slice`](DataMut::as_mut_slice);
/// all other methods have default implementations that delegate to
/// `<[T]>::*` via `as_mut_slice()`.
pub trait DataMut: Data {
    /// Returns the entire contents as a mutable slice.
    fn as_mut_slice(&mut self) -> &mut [Self::Elem];

    /// Returns a mutable iterator over the elements.
    #[inline(always)]
    fn iter_mut(&mut self) -> IterMut<'_, Self::Elem> {
        self.as_mut_slice().iter_mut()
    }

    /// Fills the entire buffer with clones of `value`.
    #[inline(always)]
    fn fill(&mut self, value: Self::Elem)
    where
        Self::Elem: Clone,
    {
        self.as_mut_slice().fill(value);
    }

    /// Copies all elements from `src` into `self`. Lengths must match.
    #[inline(always)]
    fn copy_from_slice(&mut self, src: &[Self::Elem])
    where
        Self::Elem: Copy,
    {
        self.as_mut_slice().copy_from_slice(src);
    }

    /// Returns a mutable iterator over `chunk_size` elements at a time.
    #[inline(always)]
    fn chunks_exact_mut(
        &mut self,
        chunk_size: usize,
    ) -> std::slice::ChunksExactMut<'_, Self::Elem> {
        self.as_mut_slice().chunks_exact_mut(chunk_size)
    }

    /// Divides the mutable buffer into two slices at `mid`.
    ///
    /// # Panics
    /// Panics if `mid > self.len()`.
    #[inline(always)]
    fn split_at_mut(&mut self, mid: usize) -> (&mut [Self::Elem], &mut [Self::Elem]) {
        self.as_mut_slice().split_at_mut(mid)
    }

    /// Divides the mutable buffer into two slices at `mid`, without bounds checking.
    ///
    /// # Safety
    /// The caller must ensure `0 <= mid <= self.len()`.
    #[inline(always)]
    unsafe fn split_at_mut_unchecked(
        &mut self,
        mid: usize,
    ) -> (&mut [Self::Elem], &mut [Self::Elem]) {
        unsafe { self.as_mut_slice().split_at_mut_unchecked(mid) }
    }

    /// Returns a mutable reference to the first element, or `None` if empty.
    #[inline(always)]
    fn first_mut(&mut self) -> Option<&mut Self::Elem> {
        self.as_mut_slice().first_mut()
    }

    /// Returns a mutable reference to the last element, or `None` if empty.
    #[inline(always)]
    fn last_mut(&mut self) -> Option<&mut Self::Elem> {
        self.as_mut_slice().last_mut()
    }

    /// Reverses the order of elements in place.
    #[inline(always)]
    fn reverse(&mut self) {
        self.as_mut_slice().reverse();
    }

    /// Splits the mutable buffer into a prefix of `N`-element chunks and a
    /// remainder.
    ///
    /// The remainder has fewer than `N` elements.
    #[inline(always)]
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]) {
        self.as_mut_slice().as_chunks_mut()
    }
}

/// Owned storage that can be constructed from a slice, a `Vec`, or an
/// iterator, and consumed back into an iterator.
pub trait DataOwned: Data + FromIterator<Self::Elem> {
    /// The owning iterator type returned by [`into_iter`](DataOwned::into_iter).
    type IntoIter: Iterator<Item = Self::Elem>;

    /// Creates an owned buffer from a slice by cloning each element.
    fn from_slice(data: &[Self::Elem]) -> Self
    where
        Self::Elem: Clone;

    /// Wraps a `Vec<T>` into the owned buffer type.
    fn from_vec(data: Vec<Self::Elem>) -> Self;

    /// Consumes the buffer and returns an iterator over its elements.
    fn into_iter(self) -> Self::IntoIter;
}

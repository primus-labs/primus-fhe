use core::slice::{Iter, IterMut};

/// Base trait associating a storage backend with its element type.
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
    #[must_use]
    fn as_slice(&self) -> &[Self::Elem];

    /// Returns the number of elements.
    #[must_use]
    #[inline(always)]
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the elements.
    #[must_use = "iterators are lazy and do nothing unless consumed"]
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
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    #[inline(always)]
    fn chunks_exact(&self, chunk_size: usize) -> std::slice::ChunksExact<'_, Self::Elem> {
        self.as_slice().chunks_exact(chunk_size)
    }

    /// Divides the buffer into two slices at `mid`.
    ///
    /// # Panics
    /// Panics if `mid > self.len()`.
    #[must_use]
    #[inline(always)]
    fn split_at(&self, mid: usize) -> (&[Self::Elem], &[Self::Elem]) {
        self.as_slice().split_at(mid)
    }

    /// Divides the buffer into two slices at `mid`, without bounds checking.
    ///
    /// # Safety
    /// The caller must ensure `mid <= self.len()`.
    #[must_use]
    #[inline(always)]
    unsafe fn split_at_unchecked(&self, mid: usize) -> (&[Self::Elem], &[Self::Elem]) {
        unsafe { self.as_slice().split_at_unchecked(mid) }
    }

    /// Returns the first element, or `None` if empty.
    #[must_use]
    #[inline(always)]
    fn first(&self) -> Option<&Self::Elem> {
        self.as_slice().first()
    }

    /// Returns the last element, or `None` if empty.
    #[must_use]
    #[inline(always)]
    fn last(&self) -> Option<&Self::Elem> {
        self.as_slice().last()
    }

    /// Splits the buffer into a prefix of `N`-element chunks and a remainder.
    ///
    /// The remainder has fewer than `N` elements.
    ///
    /// # Panics
    /// Panics if `N` is zero.
    #[must_use]
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
    #[must_use]
    fn as_mut_slice(&mut self) -> &mut [Self::Elem];

    /// Returns a mutable iterator over the elements.
    #[must_use = "iterators are lazy and do nothing unless consumed"]
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
    ///
    /// # Panics
    /// Panics if `src.len() != self.len()`.
    #[inline(always)]
    fn copy_from_slice(&mut self, src: &[Self::Elem])
    where
        Self::Elem: Copy,
    {
        self.as_mut_slice().copy_from_slice(src);
    }

    /// Returns a mutable iterator over `chunk_size` elements at a time.
    ///
    /// # Panics
    /// Panics if `chunk_size` is zero.
    #[must_use = "iterators are lazy and do nothing unless consumed"]
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
    #[must_use]
    #[inline(always)]
    fn split_at_mut(&mut self, mid: usize) -> (&mut [Self::Elem], &mut [Self::Elem]) {
        self.as_mut_slice().split_at_mut(mid)
    }

    /// Divides the mutable buffer into two slices at `mid`, without bounds checking.
    ///
    /// # Safety
    /// The caller must ensure `mid <= self.len()`.
    #[must_use]
    #[inline(always)]
    unsafe fn split_at_mut_unchecked(
        &mut self,
        mid: usize,
    ) -> (&mut [Self::Elem], &mut [Self::Elem]) {
        unsafe { self.as_mut_slice().split_at_mut_unchecked(mid) }
    }

    /// Returns a mutable reference to the first element, or `None` if empty.
    #[must_use]
    #[inline(always)]
    fn first_mut(&mut self) -> Option<&mut Self::Elem> {
        self.as_mut_slice().first_mut()
    }

    /// Returns a mutable reference to the last element, or `None` if empty.
    #[must_use]
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
    ///
    /// # Panics
    /// Panics if `N` is zero.
    #[must_use]
    #[inline(always)]
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]) {
        self.as_mut_slice().as_chunks_mut()
    }
}

/// Owned storage that can be constructed from a slice or a `Vec`.
///
/// Iterator construction and consumption are independent capabilities: require
/// `FromIterator` or `IntoIterator` separately at operations that need them.
pub trait DataOwned: Data {
    /// Creates an owned buffer from a slice by cloning each element.
    #[must_use]
    fn from_slice(data: &[Self::Elem]) -> Self
    where
        Self::Elem: Clone;

    /// Creates an owned buffer from a `Vec`, reusing its allocation when possible.
    #[must_use]
    fn from_vec(data: Vec<Self::Elem>) -> Self;
}

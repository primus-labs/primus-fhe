use std::sync::Arc;

use crate::ByteCount;

/// Reports the byte length of a value's logical element storage.
///
/// The count excludes container metadata, unused capacity, reference-counting
/// state, and fields that are not part of the underlying element storage.
pub trait Size {
    /// Returns the byte length of the logical element storage.
    #[must_use]
    fn byte_count(&self) -> usize;
}

impl<T: ByteCount> Size for Vec<T> {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(self.as_slice())
    }
}

impl<T: ByteCount> Size for [T] {
    #[inline]
    fn byte_count(&self) -> usize {
        self.len() * T::BYTES
    }
}

impl<S: Size + ?Sized> Size for &S {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(*self)
    }
}

impl<S: Size + ?Sized> Size for &mut S {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(&**self)
    }
}

impl<T: ByteCount, const N: usize> Size for [T; N] {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(self.as_slice())
    }
}

impl<S: Size + ?Sized> Size for Box<S> {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(self.as_ref())
    }
}

impl<S: Size + ?Sized> Size for Arc<S> {
    #[inline]
    fn byte_count(&self) -> usize {
        Size::byte_count(self.as_ref())
    }
}

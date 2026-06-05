use std::sync::Arc;

use crate::ByteCount;

/// A trait for the size of a value.
pub trait Size {
    /// Returns the size of the pointed-to value in bytes.
    fn byte_count(&self) -> usize;
}

impl<T: ByteCount> Size for Vec<T> {
    #[inline]
    fn byte_count(&self) -> usize {
        self.len() * T::BYTES
    }
}

impl<T: ByteCount> Size for &[T] {
    #[inline]
    fn byte_count(&self) -> usize {
        self.len() * T::BYTES
    }
}

impl<T: ByteCount> Size for Box<[T]> {
    #[inline]
    fn byte_count(&self) -> usize {
        self.len() * T::BYTES
    }
}

impl<T: ByteCount, const N: usize> Size for [T; N] {
    #[inline]
    fn byte_count(&self) -> usize {
        N * T::BYTES
    }
}

impl<T: ByteCount> Size for Arc<[T]> {
    #[inline]
    fn byte_count(&self) -> usize {
        self.len() * T::BYTES
    }
}

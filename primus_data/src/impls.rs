use std::sync::Arc;

use crate::traits::{Data, DataMut, DataOwned, RawData};

// ---------------------------------------------------------------------------
// &[T] — borrowed slice (read-only)
// ---------------------------------------------------------------------------

impl<T> RawData for &[T] {
    type Elem = T;
}

impl<T> Data for &[T] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        *self
    }
}

// ---------------------------------------------------------------------------
// &mut [T] — mutably borrowed slice
// ---------------------------------------------------------------------------

impl<T> RawData for &mut [T] {
    type Elem = T;
}

impl<T> Data for &mut [T] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        &**self
    }
}

impl<T> DataMut for &mut [T] {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        *self
    }
}

// ---------------------------------------------------------------------------
// [T; N] — owning fixed-size array
// ---------------------------------------------------------------------------

impl<T, const N: usize> RawData for [T; N] {
    type Elem = T;
}

impl<T, const N: usize> Data for [T; N] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<T, const N: usize> DataMut for [T; N] {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

// ---------------------------------------------------------------------------
// &[T; N] — shared reference to fixed-size array
// ---------------------------------------------------------------------------

impl<T, const N: usize> RawData for &[T; N] {
    type Elem = T;
}

impl<T, const N: usize> Data for &[T; N] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        *self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

// ---------------------------------------------------------------------------
// &mut [T; N] — exclusive reference to fixed-size array
// ---------------------------------------------------------------------------

impl<T, const N: usize> RawData for &mut [T; N] {
    type Elem = T;
}

impl<T, const N: usize> Data for &mut [T; N] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        *self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<T, const N: usize> DataMut for &mut [T; N] {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        *self
    }
}

// ---------------------------------------------------------------------------
// Vec<T> — owned heap-allocated buffer
// ---------------------------------------------------------------------------

impl<T> RawData for Vec<T> {
    type Elem = T;
}

impl<T> Data for Vec<T> {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

impl<T> DataMut for Vec<T> {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

impl<T> DataOwned for Vec<T> {
    type IntoIter = std::vec::IntoIter<T>;

    #[inline(always)]
    fn from_slice(data: &[T]) -> Self
    where
        T: Clone,
    {
        data.to_vec()
    }

    #[inline(always)]
    fn from_vec(data: Vec<T>) -> Self {
        data
    }

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        <Vec<T> as IntoIterator>::into_iter(self)
    }
}

// ---------------------------------------------------------------------------
// Box<[T]> — owned boxed slice
// ---------------------------------------------------------------------------

impl<T> RawData for Box<[T]> {
    type Elem = T;
}

impl<T> Data for Box<[T]> {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

impl<T> DataMut for Box<[T]> {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

impl<T> DataOwned for Box<[T]> {
    type IntoIter = <Box<[T]> as IntoIterator>::IntoIter;

    #[inline(always)]
    fn from_slice(data: &[T]) -> Self
    where
        T: Clone,
    {
        data.to_vec().into_boxed_slice()
    }

    #[inline(always)]
    fn from_vec(data: Vec<T>) -> Self {
        data.into_boxed_slice()
    }

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        <Box<[T]> as IntoIterator>::into_iter(self)
    }
}

// ---------------------------------------------------------------------------
// Arc<[T]> — shared owned slice
// ---------------------------------------------------------------------------

impl<T> RawData for Arc<[T]> {
    type Elem = T;
}

impl<T> Data for Arc<[T]> {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

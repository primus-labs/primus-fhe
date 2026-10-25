use std::sync::Arc;

use super::{Data, DataMut, DataOwned, RawData};

// Borrowed slices.

impl<T> RawData for &[T] {
    type Elem = T;
}

impl<T> Data for &[T] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

impl<T> RawData for &mut [T] {
    type Elem = T;
}

impl<T> Data for &mut [T] {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

impl<T> DataMut for &mut [T] {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

// Fixed-size arrays.

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

// References preserve the underlying storage capabilities. RawData is Sized,
// so these impls do not overlap the explicit borrowed-slice impls above.

impl<S: RawData> RawData for &S {
    type Elem = S::Elem;
}

impl<S: Data> Data for &S {
    #[inline(always)]
    fn as_slice(&self) -> &[Self::Elem] {
        S::as_slice(self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        S::len(self)
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        S::is_empty(self)
    }
}

impl<S: RawData> RawData for &mut S {
    type Elem = S::Elem;
}

impl<S: Data> Data for &mut S {
    #[inline(always)]
    fn as_slice(&self) -> &[Self::Elem] {
        S::as_slice(self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        S::len(self)
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        S::is_empty(self)
    }
}

impl<S: DataMut> DataMut for &mut S {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [Self::Elem] {
        S::as_mut_slice(self)
    }
}

// Standard owned storage.

impl<T> RawData for Vec<T> {
    type Elem = T;
}

impl<T> Data for Vec<T> {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len()
    }
}

impl<T> DataMut for Vec<T> {
    #[inline(always)]
    fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

impl<T> DataOwned for Vec<T> {
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
}

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
}

impl<T> RawData for Arc<[T]> {
    type Elem = T;
}

impl<T> Data for Arc<[T]> {
    #[inline(always)]
    fn as_slice(&self) -> &[T] {
        self
    }
}

#[cfg(feature = "aligned-vec")]
mod aligned {
    use aligned_vec::{ABox, AVec, Alignment};

    use super::{Data, DataMut, RawData};

    impl<T, A: Alignment> RawData for AVec<T, A> {
        type Elem = T;
    }

    impl<T, A: Alignment> Data for AVec<T, A> {
        #[inline(always)]
        fn as_slice(&self) -> &[T] {
            AVec::as_slice(self)
        }

        #[inline(always)]
        fn len(&self) -> usize {
            AVec::len(self)
        }
    }

    impl<T, A: Alignment> DataMut for AVec<T, A> {
        #[inline(always)]
        fn as_mut_slice(&mut self) -> &mut [T] {
            AVec::as_mut_slice(self)
        }
    }

    impl<T, A: Alignment> RawData for ABox<[T], A> {
        type Elem = T;
    }

    impl<T, A: Alignment> Data for ABox<[T], A> {
        #[inline(always)]
        fn as_slice(&self) -> &[T] {
            self
        }
    }

    impl<T, A: Alignment> DataMut for ABox<[T], A> {
        #[inline(always)]
        fn as_mut_slice(&mut self) -> &mut [T] {
            self
        }
    }
}

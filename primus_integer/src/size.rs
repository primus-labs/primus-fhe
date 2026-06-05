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

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_size_per_type {
		($($T:ty),*; $($W:literal),*) => {
			$(
				let v : Vec<$T> = Vec::<$T>::from([1,2,3,4]);
                assert_eq!(v.byte_count(), $W*4);

				let slice_v : &[$T] = &Vec::<$T>::from([1,2,3,4]);
                assert_eq!(slice_v.byte_count(), $W*4);

				let boxed: Box<[$T]> = Vec::<$T>::from([1,2,3,4]).into_boxed_slice();
                assert_eq!(boxed.byte_count(), $W*4);

				let arr = [1 as $T; 4];
                assert_eq!(arr.byte_count(), $W*4);

				let a: Arc<[$T]> = Arc::from([1 as $T,2,3,4]);
                assert_eq!(a.byte_count(), $W*4);

			)*
		};
	}

    #[test]
    fn test_size() {
        #[cfg(target_pointer_width = "32")]
        test_size_per_type!(
            i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize;
             1,  1,   2,   2,   4,   4,   8,   8,   16,   16,     4,     4
        );
        #[cfg(target_pointer_width = "64")]
        test_size_per_type!(
            i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize;
             1,  1,   2,   2,   4,   4,   8,   8,   16,   16,     8,     8
        );
    }
}

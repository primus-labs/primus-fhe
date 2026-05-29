#[cfg(not(feature = "simd"))]
mod scalar {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::{UintModulus, common::uint::slice};

    impl<T: FheUint> ReduceOnceSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_once_slice_assign(self, values: &mut [T]) {
            slice::reduce_once_slice_assign(self.0, values);
        }
        #[inline]
        fn reduce_once_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_once_slice_to(self.0, input, output);
        }
    }
    impl<T: FheUint> ReduceNegSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_neg_slice_assign(self, values: &mut [T]) {
            slice::reduce_neg_slice_assign(self.0, values);
        }
        #[inline]
        fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_neg_slice_to(self.0, input, output);
        }
    }
    impl<T: FheUint> ReduceAddSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]) {
            slice::reduce_add_slice_assign(self.0, a, b);
        }
        #[inline]
        fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            slice::reduce_add_slice_to(self.0, a, b, output);
        }
    }
    impl<T: FheUint> ReduceSubSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
            slice::reduce_sub_slice_assign(self.0, a, b);
        }
        #[inline]
        fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            slice::reduce_sub_slice_to(self.0, a, b, output);
        }
        #[inline]
        fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
            slice::reduce_sub_slice_rev_assign(self.0, a, b);
        }
    }
    impl<T: FheUint> ReduceDoubleSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_double_slice_assign(self, values: &mut [T]) {
            slice::reduce_double_slice_assign(self.0, values);
        }
        #[inline]
        fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_double_slice_to(self.0, input, output);
        }
    }
}

#[cfg(feature = "simd")]
mod simd {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::UintModulus;
    use crate::common::uint::simd;

    impl<T: FheUint> ReduceOnceSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_once_slice_assign(self, values: &mut [T]) {
            simd::reduce_once_slice_assign::<T>(self.0, values)
        }
        #[inline]
        fn reduce_once_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_once_slice_to::<T>(self.0, input, output)
        }
    }
    impl<T: FheUint> ReduceNegSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_neg_slice_assign(self, values: &mut [T]) {
            simd::reduce_neg_slice_assign(self.0, values);
        }
        #[inline]
        fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_neg_slice_to(self.0, input, output);
        }
    }
    impl<T: FheUint> ReduceAddSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]) {
            simd::reduce_add_slice_assign(self.0, a, b);
        }
        #[inline]
        fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            simd::reduce_add_slice_to(self.0, a, b, output)
        }
    }
    impl<T: FheUint> ReduceSubSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
            simd::reduce_sub_slice_assign(self.0, a, b)
        }
        #[inline]
        fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            simd::reduce_sub_slice_to(self.0, a, b, output);
        }
        #[inline]
        fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
            simd::reduce_sub_slice_rev_assign(self.0, a, b);
        }
    }
    impl<T: FheUint> ReduceDoubleSlice<T> for UintModulus<T> {
        #[inline]
        fn reduce_double_slice_assign(self, values: &mut [T]) {
            simd::reduce_double_slice_assign::<T>(self.0, values);
        }
        #[inline]
        fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_double_slice_to::<T>(self.0, input, output);
        }
    }
}

use primus_integer::FheUint;
use primus_reduce::{ReduceError, prelude::*};

use crate::{UintModulus, common::uint::slice};

impl<T: FheUint> ReduceInvSlice<T> for UintModulus<T> {
    #[inline]
    fn reduce_inv_slice_assign(self, values: &mut [T], scratch: &mut [T]) {
        slice::reduce_inv_slice_assign(self.0, values, scratch);
    }
    #[inline]
    fn reduce_inv_slice_to(self, input: &[T], output: &mut [T]) {
        slice::reduce_inv_slice_to(self.0, input, output);
    }
}

impl<T: FheUint> TryReduceInvSlice<T> for UintModulus<T> {
    #[inline]
    fn try_reduce_inv_slice_assign(
        self,
        values: &mut [T],
        scratch: &mut [T],
    ) -> Result<(), ReduceError<T>> {
        slice::try_reduce_inv_slice_assign(self.0, values, scratch)
    }
    #[inline]
    fn try_reduce_inv_slice_to(self, input: &[T], output: &mut [T]) -> Result<(), ReduceError<T>> {
        slice::try_reduce_inv_slice_to(self.0, input, output)
    }
}

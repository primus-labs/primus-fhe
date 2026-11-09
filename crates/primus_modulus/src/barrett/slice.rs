use primus_integer::FheUint;
use primus_reduce::{ReduceAddSlice, ReduceDotProductSigned, ReduceSubSlice};

use super::BarrettModulus;
use crate::common::compact::slice;

// Let LLVM vectorize the actual add/sub ranges, including the split slices
// used by monomial accumulation, without fixed-lane chunk/tail handling.
impl<T: FheUint> ReduceAddSlice<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]) {
        slice::reduce_add_slice_assign(self.value, a, b);
    }
    #[inline]
    fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        slice::reduce_add_slice_to(self.value, a, b, output);
    }
}

impl<T: FheUint> ReduceSubSlice<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
        slice::reduce_sub_slice_assign(self.value, a, b);
    }
    #[inline]
    fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        slice::reduce_sub_slice_to(self.value, a, b, output);
    }
    #[inline]
    fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
        slice::reduce_sub_slice_rev_assign(self.value, a, b);
    }
}

#[cfg(not(feature = "simd"))]
mod basic {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::{BarrettModulus, common::compact::slice};

    impl<T: FheUint> ReduceOnceSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_once_slice_assign(self, values: &mut [T]) {
            slice::reduce_once_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_once_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_once_slice_to(self.value, input, output);
        }
    }
    impl<T: FheUint> ReduceNegSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_neg_slice_assign(self, values: &mut [T]) {
            slice::reduce_neg_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_neg_slice_to(self.value, input, output);
        }
    }
    impl<T: FheUint> ReduceDoubleSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_double_slice_assign(self, values: &mut [T]) {
            slice::reduce_double_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
            slice::reduce_double_slice_to(self.value, input, output);
        }
    }

    impl<T: FheUint> LazyReduceSubSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
            slice::lazy_reduce_sub_slice_assign(self.value, a, b);
        }

        #[inline]
        fn lazy_reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            slice::lazy_reduce_sub_slice_to(self.value, a, b, output);
        }

        #[inline]
        fn lazy_reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
            slice::lazy_reduce_sub_slice_rev_assign(self.value, a, b);
        }
    }

    impl<T: FheUint> LazyReduceNegSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_neg_slice_assign(self, values: &mut [T]) {
            slice::lazy_reduce_neg_slice_assign(self.value, values);
        }

        #[inline]
        fn lazy_reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            slice::lazy_reduce_neg_slice_to(self.value, input, output);
        }
    }
}

#[cfg(feature = "simd")]
mod basic {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::{BarrettModulus, common::compact::simd};

    impl<T: FheUint> ReduceOnceSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_once_slice_assign(self, values: &mut [T]) {
            simd::reduce_once_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_once_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_once_slice_to(self.value, input, output);
        }
    }
    impl<T: FheUint> ReduceNegSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_neg_slice_assign(self, values: &mut [T]) {
            simd::reduce_neg_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_neg_slice_to(self.value, input, output);
        }
    }
    impl<T: FheUint> ReduceDoubleSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_double_slice_assign(self, values: &mut [T]) {
            simd::reduce_double_slice_assign(self.value, values);
        }
        #[inline]
        fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
            simd::reduce_double_slice_to(self.value, input, output);
        }
    }

    impl<T: FheUint> LazyReduceSubSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
            simd::lazy_reduce_sub_slice_assign(self.value, a, b);
        }

        #[inline]
        fn lazy_reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            simd::lazy_reduce_sub_slice_to(self.value, a, b, output);
        }

        #[inline]
        fn lazy_reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
            simd::lazy_reduce_sub_slice_rev_assign(self.value, a, b);
        }
    }

    impl<T: FheUint> LazyReduceNegSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_neg_slice_assign(self, values: &mut [T]) {
            simd::lazy_reduce_neg_slice_assign(self.value, values);
        }

        #[inline]
        fn lazy_reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
            simd::lazy_reduce_neg_slice_to(self.value, input, output);
        }
    }
}

#[cfg(not(feature = "simd"))]
mod mul {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::{BarrettModulus, common::compact::slice};

    impl<T: FheUint> LazyReduceMulSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
            slice::lazy_reduce_mul_slice_assign(self, a, b);
        }

        #[inline]
        fn lazy_reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            slice::lazy_reduce_mul_slice_to(self, a, b, output);
        }

        #[inline]
        fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
            slice::lazy_reduce_mul_scalar_slice_assign(self, a, scalar);
        }

        #[inline]
        fn lazy_reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
            slice::lazy_reduce_mul_scalar_slice_to(self, a, scalar, output);
        }
    }

    impl<T: FheUint> LazyReduceMulAddSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            slice::lazy_reduce_add_mul_slice_assign(self, acc, a, b);
        }

        #[inline]
        fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            slice::lazy_reduce_sub_mul_slice_assign(self, acc, a, b);
        }

        #[inline]
        fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T) {
            slice::lazy_reduce_add_mul_scalar_slice_assign(self, acc, a, scalar);
        }

        #[inline]
        fn lazy_reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
            slice::lazy_reduce_mul_add_slice_to(self, a, b, c, output);
        }

        #[inline]
        fn lazy_reduce_mul_scalar_add_slice_to(
            self,
            a: &[T],
            scalar: T,
            c: &[T],
            output: &mut [T],
        ) {
            slice::lazy_reduce_mul_scalar_add_slice_to(self, a, scalar, c, output);
        }
    }

    impl<T: FheUint> ReduceMulSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
            slice::reduce_mul_slice_assign(self, a, b);
        }

        #[inline]
        fn reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            slice::reduce_mul_slice_to(self, a, b, output);
        }

        #[inline]
        fn reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
            slice::reduce_mul_scalar_slice_assign(self, a, scalar);
        }

        #[inline]
        fn reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
            slice::reduce_mul_scalar_slice_to(self, a, scalar, output);
        }
    }

    impl<T: FheUint> ReduceMulAddSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            if super::super::native::try_add_mul::<T, false>(self, acc, a, b) {
                return;
            }
            slice::reduce_add_mul_slice_assign(self, acc, a, b);
        }

        #[inline]
        fn reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            slice::reduce_sub_mul_slice_assign(self, acc, a, b);
        }

        #[inline]
        fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T) {
            slice::reduce_add_mul_scalar_slice_assign(self, acc, a, scalar);
        }

        #[inline]
        fn reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
            if super::super::native::try_mul_add_to::<T, false>(self, a, b, c, output) {
                return;
            }
            slice::reduce_mul_add_slice_to(self, a, b, c, output);
        }

        #[inline]
        fn reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]) {
            slice::reduce_mul_scalar_add_slice_to(self, a, scalar, c, output);
        }
    }
}

#[cfg(feature = "simd")]
mod mul {
    use primus_integer::FheUint;
    use primus_reduce::prelude::*;

    use crate::{BarrettModulus, SimdBarrettModulus, common::compact::simd};

    impl<T: FheUint> LazyReduceMulSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
            simd::lazy_reduce_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b,
            );
        }

        #[inline]
        fn lazy_reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            simd::lazy_reduce_mul_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b, output,
            );
        }

        #[inline]
        fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
            simd::lazy_reduce_mul_scalar_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar,
            );
        }

        #[inline]
        fn lazy_reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
            simd::lazy_reduce_mul_scalar_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar, output,
            );
        }
    }

    impl<T: FheUint> LazyReduceMulAddSlice<T> for BarrettModulus<T> {
        #[inline]
        fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            simd::lazy_reduce_add_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, acc, a, b,
            );
        }

        #[inline]
        fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            simd::lazy_reduce_sub_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, acc, a, b,
            );
        }

        #[inline]
        fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T) {
            simd::lazy_reduce_add_mul_scalar_slice_assign::<
                T,
                BarrettModulus<T>,
                SimdBarrettModulus<T>,
            >(self, acc, a, scalar);
        }

        #[inline]
        fn lazy_reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
            simd::lazy_reduce_mul_add_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b, c, output,
            );
        }

        #[inline]
        fn lazy_reduce_mul_scalar_add_slice_to(
            self,
            a: &[T],
            scalar: T,
            c: &[T],
            output: &mut [T],
        ) {
            simd::lazy_reduce_mul_scalar_add_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar, c, output,
            );
        }
    }

    impl<T: FheUint> ReduceMulSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
            simd::reduce_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b,
            );
        }

        #[inline]
        fn reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
            simd::reduce_mul_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b, output,
            );
        }

        #[inline]
        fn reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
            simd::reduce_mul_scalar_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar,
            );
        }

        #[inline]
        fn reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
            simd::reduce_mul_scalar_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar, output,
            );
        }
    }

    impl<T: FheUint> ReduceMulAddSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            if super::super::native::try_add_mul::<T, false>(self, acc, a, b) {
                return;
            }
            simd::reduce_add_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, acc, a, b,
            );
        }

        #[inline]
        fn reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
            simd::reduce_sub_mul_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, acc, a, b,
            );
        }

        #[inline]
        fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T) {
            simd::reduce_add_mul_scalar_slice_assign::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, acc, a, scalar,
            );
        }

        #[inline]
        fn reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
            if super::super::native::try_mul_add_to::<T, false>(self, a, b, c, output) {
                return;
            }
            simd::reduce_mul_add_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, b, c, output,
            );
        }

        #[inline]
        fn reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]) {
            simd::reduce_mul_scalar_add_slice_to::<T, BarrettModulus<T>, SimdBarrettModulus<T>>(
                self, a, scalar, c, output,
            );
        }
    }
}

#[cfg(not(feature = "simd"))]
mod dot_product {
    use primus_integer::FheUint;
    use primus_reduce::ReduceDotProduct;

    use crate::{BarrettModulus, common::compact::slice};

    /// Both entry points accept operands below `2^(T::BITS - 2)`, independently
    /// of the destination modulus. See [`BarrettModulus`] for the input contract.
    impl<T: FheUint> ReduceDotProduct<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_dot_product(self, a: &[T], b: &[T]) -> T {
            slice::reduce_dot_product(self, a, b)
        }

        #[inline]
        fn reduce_dot_product_iter(
            self,
            a: impl IntoIterator<Item = T>,
            b: impl IntoIterator<Item = T>,
        ) -> T {
            slice::reduce_dot_product_iter(self, a, b)
        }
    }
}

#[cfg(feature = "simd")]
mod dot_product {
    use primus_integer::FheUint;
    use primus_reduce::ReduceDotProduct;

    use crate::{BarrettModulus, common::compact::slice};

    /// Both entry points accept operands below `2^(T::BITS - 2)`, independently
    /// of the destination modulus. See [`BarrettModulus`] for the input contract.
    impl<T: FheUint> ReduceDotProduct<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_dot_product(self, a: &[T], b: &[T]) -> T {
            assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

            let outer = crate::common::compact::DOT_PRODUCT_INNER_CHUNK * T::LANE_COUNT;
            if a.len() < outer {
                slice::reduce_dot_product(self, a, b)
            } else {
                crate::barrett_simd_reduce_dot_product(self, a, b)
            }
        }

        #[inline]
        fn reduce_dot_product_iter(
            self,
            a: impl IntoIterator<Item = T>,
            b: impl IntoIterator<Item = T>,
        ) -> T {
            slice::reduce_dot_product_iter(self, a, b)
        }
    }
}

mod inv {
    use primus_integer::FheUint;
    use primus_reduce::{ReduceError, prelude::*};

    use crate::BarrettModulus;

    impl<T: FheUint> ReduceInvSlice<T> for BarrettModulus<T> {
        #[inline]
        fn reduce_inv_slice_to(self, input: &[T], output: &mut [T]) {
            let len = input.len();

            debug_assert_eq!(output.len(), len);

            if len == 0 {
                return;
            }

            let mut total_product = T::ONE;
            for (prefix_product, &value) in output.iter_mut().zip(input.iter()) {
                *prefix_product = total_product;
                total_product = self.reduce_mul(total_product, value);
            }

            let mut suffix_inverse = self.reduce_inv(total_product);

            for (&value, prefix_product) in input.iter().rev().zip(output.iter_mut().rev()) {
                self.reduce_mul_assign(prefix_product, suffix_inverse);
                suffix_inverse = self.reduce_mul(suffix_inverse, value);
            }
        }
    }

    impl<T: FheUint> TryReduceInvSlice<T> for BarrettModulus<T> {
        #[inline]
        fn try_reduce_inv_slice_to(
            self,
            input: &[T],
            output: &mut [T],
        ) -> Result<(), ReduceError<T>> {
            let len = input.len();

            debug_assert_eq!(output.len(), len);

            if len == 0 {
                return Ok(());
            }

            let mut total_product = T::ONE;
            for (prefix_product, &value) in output.iter_mut().zip(input.iter()) {
                *prefix_product = total_product;
                total_product = self.reduce_mul(total_product, value);
            }

            let mut suffix_inverse = self.try_reduce_inv(total_product)?;

            for (&value, prefix_product) in input.iter().rev().zip(output.iter_mut().rev()) {
                self.reduce_mul_assign(prefix_product, suffix_inverse);
                suffix_inverse = self.reduce_mul(suffix_inverse, value);
            }

            Ok(())
        }
    }
}

impl<T: FheUint> ReduceDotProductSigned<T> for BarrettModulus<T> {
    #[inline]
    fn reduce_dot_product_signed(self, lhs: &[T], rhs: &[T::SignedInteger]) -> T {
        #[cfg(not(feature = "simd"))]
        {
            crate::common::compact::slice::reduce_dot_product_signed(self, lhs, rhs)
        }
        #[cfg(feature = "simd")]
        {
            crate::barrett_simd_reduce_dot_product_signed(self, lhs, rhs)
        }
    }
}

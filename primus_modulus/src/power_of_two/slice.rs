use primus_integer::FheUint;
use primus_reduce::prelude::*;

use super::PowOf2Modulus;

impl<T: FheUint> ReduceOnceSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_once_slice_assign(self, values: &mut [T]) {
        values.iter_mut().for_each(|v| *v &= self.mask);
    }
    #[inline]
    fn reduce_once_slice_to(self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), output.len());
        output
            .iter_mut()
            .zip(input)
            .for_each(|(x, &y)| *x = y & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceNegSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_neg_slice_assign(self, values: &mut [T]) {
        values
            .iter_mut()
            .for_each(|v| *v = v.wrapping_neg() & self.mask);
    }
    #[inline]
    fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), output.len());
        output
            .iter_mut()
            .zip(input)
            .for_each(|(x, &y)| *x = y.wrapping_neg() & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceAddSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());
        a.iter_mut()
            .zip(b)
            .for_each(|(x, &y)| *x = x.wrapping_add(y) & self.mask);
    }
    #[inline]
    fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(output.len(), a.len());
        debug_assert_eq!(output.len(), b.len());
        output
            .iter_mut()
            .zip(a)
            .zip(b)
            .for_each(|((out, &x), &y)| *out = x.wrapping_add(y) & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceSubSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());
        a.iter_mut()
            .zip(b)
            .for_each(|(x, &y)| *x = x.wrapping_sub(y) & self.mask);
    }
    #[inline]
    fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(output.len(), a.len());
        debug_assert_eq!(output.len(), b.len());
        output
            .iter_mut()
            .zip(a)
            .zip(b)
            .for_each(|((out, &x), &y)| *out = x.wrapping_sub(y) & self.mask);
    }
    #[inline]
    fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter_mut())
            .for_each(|(&x, y)| *y = x.wrapping_sub(*y) & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceDoubleSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_double_slice_assign(self, values: &mut [T]) {
        values
            .iter_mut()
            .for_each(|v| *v = v.wrapping_shl(1) & self.mask);
    }
    #[inline]
    fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), output.len());
        output
            .iter_mut()
            .zip(input)
            .for_each(|(x, &y)| *x = y.wrapping_shl(1) & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceMulSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());
        a.iter_mut().zip(b).for_each(|(x, &y)| {
            *x = x.wrapping_mul(y) & self.mask;
        });
    }
    #[inline]
    fn reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(output.len(), a.len());
        debug_assert_eq!(output.len(), b.len());
        output.iter_mut().zip(a).zip(b).for_each(|((out, &x), &y)| {
            *out = x.wrapping_mul(y) & self.mask;
        });
    }
    #[inline]
    fn reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
        a.iter_mut().for_each(|x| {
            *x = x.wrapping_mul(scalar) & self.mask;
        });
    }
    #[inline]
    fn reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
        debug_assert_eq!(a.len(), output.len());
        output
            .iter_mut()
            .zip(a)
            .for_each(|(out, &x)| *out = x.wrapping_mul(scalar) & self.mask);
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceMulAddSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        debug_assert_eq!(acc.len(), a.len());
        debug_assert_eq!(acc.len(), b.len());
        acc.iter_mut().zip(a).zip(b).for_each(|((acc, &a), &b)| {
            *acc = a.wrapping_mul(b).wrapping_add(*acc) & self.mask;
        });
    }
    #[inline]
    fn reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        debug_assert_eq!(acc.len(), a.len());
        debug_assert_eq!(acc.len(), b.len());
        acc.iter_mut().zip(a).zip(b).for_each(|((acc, &a), &b)| {
            *acc = acc.wrapping_sub(a.wrapping_mul(b)) & self.mask;
        });
    }
    #[inline]
    fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], b: &[T], scalar: T) {
        debug_assert_eq!(acc.len(), b.len());
        acc.iter_mut().zip(b).for_each(|(acc, &b)| {
            *acc = scalar.wrapping_mul(b).wrapping_add(*acc) & self.mask;
        });
    }
    #[inline]
    fn reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), c.len());
        debug_assert_eq!(a.len(), output.len());
        a.iter()
            .zip(b)
            .zip(c)
            .zip(output)
            .for_each(|(((&a, &b), &c), o)| {
                *o = a.wrapping_mul(b).wrapping_add(c) & self.mask;
            });
    }
    #[inline]
    fn reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), c.len());
        debug_assert_eq!(a.len(), output.len());
        a.iter().zip(c).zip(output).for_each(|((&a, &c), o)| {
            *o = a.wrapping_mul(scalar).wrapping_add(c) & self.mask;
        });
    }
}

#[cfg(not(feature = "simd"))]
impl<T: FheUint> ReduceDotProduct<T> for PowOf2Modulus<T> {
    type Output = T;
    #[inline]
    fn reduce_dot_product(self, a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> T {
        let a = a.as_ref();
        let b = b.as_ref();
        assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");
        a.iter()
            .zip(b)
            .fold(T::ZERO, |acc, (&x, &y)| x.wrapping_mul(y).wrapping_add(acc))
            & self.mask
    }
    #[inline]
    fn reduce_dot_product_iter(
        self,
        a: impl IntoIterator<Item = T>,
        b: impl IntoIterator<Item = T>,
    ) -> T {
        std::iter::zip(a, b).fold(T::ZERO, |acc, (x, y)| x.wrapping_mul(y).wrapping_add(acc))
            & self.mask
    }
}

impl<T: FheUint> LazyReduceMulSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn lazy_reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
        self.reduce_mul_slice_assign(a, b);
    }
    #[inline]
    fn lazy_reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        self.reduce_mul_slice_to(a, b, output);
    }
    #[inline]
    fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
        self.reduce_mul_scalar_slice_assign(a, scalar);
    }
    #[inline]
    fn lazy_reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
        self.reduce_mul_scalar_slice_to(a, scalar, output);
    }
}

impl<T: FheUint> LazyReduceMulAddSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        self.reduce_add_mul_slice_assign(acc, a, b);
    }
    #[inline]
    fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        self.reduce_sub_mul_slice_assign(acc, a, b);
    }
    #[inline]
    fn lazy_reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
        self.reduce_mul_add_slice_to(a, b, c, output);
    }
    #[inline]
    fn lazy_reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]) {
        self.reduce_mul_scalar_add_slice_to(a, scalar, c, output);
    }

    #[inline]
    fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], a: &[T], scalar: T) {
        self.reduce_add_mul_scalar_slice_assign(acc, a, scalar);
    }
}

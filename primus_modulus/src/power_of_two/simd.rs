use core::simd::num::SimdUint;

use primus_integer::{FheUint, SimdArray};
use primus_reduce::prelude::*;

use super::PowOf2Modulus;

impl<T: FheUint> ReduceNegSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_neg_slice_assign(self, values: &mut [T]) {
        let mask = T::SimdT::splat(self.mask);

        let (chunks, rem) = T::simd_as_chunks_mut(values);

        for chunk in chunks {
            let v = T::SimdT::from_array(*chunk);
            *chunk = (v.wrapping_neg() & mask).to_array();
        }

        for v in rem {
            *v = v.wrapping_neg() & self.mask;
        }
    }
    #[inline]
    fn reduce_neg_slice_to(self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), output.len());

        let mask = T::SimdT::splat(self.mask);

        let (in_chunks, in_rem) = T::simd_as_chunks(input);
        let (out_chunks, out_rem) = T::simd_as_chunks_mut(output);

        for (i, o) in in_chunks.iter().zip(out_chunks) {
            let v = T::SimdT::from_array(*i);
            *o = (v.wrapping_neg() & mask).to_array();
        }

        for (&i, o) in in_rem.iter().zip(out_rem) {
            *o = i.wrapping_neg() & self.mask;
        }
    }
}

impl<T: FheUint> ReduceAddSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_add_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *ac = ((av + bv) & mask).to_array();
        }

        for (a, &b) in a_rem.iter_mut().zip(b_rem) {
            *a = a.wrapping_add(b) & self.mask;
        }
    }

    #[inline]
    fn reduce_add_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *oc = ((av + bv) & mask).to_array();
        }

        for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
            *o = a.wrapping_add(b) & self.mask;
        }
    }
}

impl<T: FheUint> ReduceSubSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_sub_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *ac = ((av - bv) & mask).to_array();
        }

        for (a, &b) in a_rem.iter_mut().zip(b_rem) {
            *a = a.wrapping_sub(b) & self.mask;
        }
    }

    #[inline]
    fn reduce_sub_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *oc = ((av - bv) & mask).to_array();
        }

        for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
            *o = a.wrapping_sub(b) & self.mask;
        }
    }

    #[inline]
    fn reduce_sub_slice_rev_assign(self, a: &[T], b: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks_mut(b);

        for (ac, bc) in a_chunks.iter().zip(b_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *bc = ((av - bv) & mask).to_array();
        }

        for (&a, b) in a_rem.iter().zip(b_rem) {
            *b = a.wrapping_sub(*b) & self.mask;
        }
    }
}
impl<T: FheUint> ReduceDoubleSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_double_slice_assign(self, values: &mut [T]) {
        let mask = T::SimdT::splat(self.mask);
        let shl = T::SimdT::splat(T::ONE);

        let (v_chunks, v_rem) = T::simd_as_chunks_mut(values);

        for vc in v_chunks.iter_mut() {
            let v = T::SimdT::from_array(*vc);
            *vc = ((v << shl) & mask).to_array();
        }

        for v in v_rem.iter_mut() {
            *v = v.wrapping_shl(1) & self.mask;
        }
    }

    #[inline]
    fn reduce_double_slice_to(self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), output.len());

        let mask = T::SimdT::splat(self.mask);
        let shl = T::SimdT::splat(T::ONE);

        let (in_chunks, in_rem) = T::simd_as_chunks(input);
        let (out_chunks, out_rem) = T::simd_as_chunks_mut(output);

        for (i, o) in in_chunks.iter().zip(out_chunks) {
            let v = T::SimdT::from_array(*i);
            *o = ((v << shl) & mask).to_array();
        }

        for (&i, o) in in_rem.iter().zip(out_rem) {
            *o = i.wrapping_shl(1) & self.mask;
        }
    }
}

impl<T: FheUint> ReduceDotProduct<T> for PowOf2Modulus<T> {
    type Output = T;
    #[inline]
    fn reduce_dot_product(self, a: impl AsRef<[T]>, b: impl AsRef<[T]>) -> T {
        let a = a.as_ref();
        let b = b.as_ref();
        assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        let mut acc = T::SimdT::splat(T::ZERO);
        for (ac, bc) in a_chunks.iter().zip(b_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            acc += av * bv;
        }

        let mut result = acc.reduce_sum();
        for (&a, &b) in a_rem.iter().zip(b_rem) {
            result = result.wrapping_add(a.wrapping_mul(b));
        }

        result & self.mask
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

impl<T: FheUint> ReduceMulSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_mul_slice_assign(self, a: &mut [T], b: &[T]) {
        debug_assert_eq!(a.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *ac = ((av * bv) & mask).to_array();
        }

        for (a, &b) in a_rem.iter_mut().zip(b_rem) {
            *a = a.wrapping_mul(b) & self.mask;
        }
    }

    #[inline]
    fn reduce_mul_slice_to(self, a: &[T], b: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            *oc = ((av * bv) & mask).to_array();
        }

        for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
            *o = a.wrapping_mul(b) & self.mask;
        }
    }
    #[inline]
    fn reduce_mul_scalar_slice_assign(self, a: &mut [T], scalar: T) {
        let mask = T::SimdT::splat(self.mask);
        let s = T::SimdT::splat(scalar);

        let (chunks, rem) = T::simd_as_chunks_mut(a);

        for chunk in chunks {
            let v = T::SimdT::from_array(*chunk);
            *chunk = ((v * s) & mask).to_array();
        }

        for v in rem {
            *v = v.wrapping_mul(scalar) & self.mask;
        }
    }
    #[inline]
    fn reduce_mul_scalar_slice_to(self, a: &[T], scalar: T, output: &mut [T]) {
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);
        let s = T::SimdT::splat(scalar);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for (ac, oc) in a_chunks.iter().zip(o_chunks) {
            let v = T::SimdT::from_array(*ac);
            *oc = ((v * s) & mask).to_array();
        }

        for (&a, o) in a_rem.iter().zip(o_rem) {
            *o = a.wrapping_mul(scalar) & self.mask;
        }
    }
}

impl<T: FheUint> ReduceMulAddSlice<T> for PowOf2Modulus<T> {
    #[inline]
    fn reduce_add_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        debug_assert_eq!(acc.len(), a.len());
        debug_assert_eq!(acc.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for ((ac, av_slice), bv_slice) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
            let acc_v = T::SimdT::from_array(*ac);
            let a_v = T::SimdT::from_array(*av_slice);
            let b_v = T::SimdT::from_array(*bv_slice);
            *ac = ((acc_v + a_v * b_v) & mask).to_array();
        }

        for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
            *acc = acc.wrapping_add(a.wrapping_mul(b)) & self.mask;
        }
    }
    #[inline]
    fn reduce_sub_mul_slice_assign(self, acc: &mut [T], a: &[T], b: &[T]) {
        debug_assert_eq!(acc.len(), a.len());
        debug_assert_eq!(acc.len(), b.len());

        let mask = T::SimdT::splat(self.mask);

        let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for ((ac, av_slice), bv_slice) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
            let acc_v = T::SimdT::from_array(*ac);
            let a_v = T::SimdT::from_array(*av_slice);
            let b_v = T::SimdT::from_array(*bv_slice);
            *ac = ((acc_v - a_v * b_v) & mask).to_array();
        }

        for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
            *acc = acc.wrapping_sub(a.wrapping_mul(b)) & self.mask;
        }
    }
    #[inline]
    fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [T], b: &[T], scalar: T) {
        debug_assert_eq!(acc.len(), b.len());

        let mask = T::SimdT::splat(self.mask);
        let s = T::SimdT::splat(scalar);

        let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);

        for (ac, bc) in acc_chunks.iter_mut().zip(b_chunks) {
            let acc_v = T::SimdT::from_array(*ac);
            let b_v = T::SimdT::from_array(*bc);
            *ac = ((acc_v + s * b_v) & mask).to_array();
        }

        for (acc, &b) in acc_rem.iter_mut().zip(b_rem) {
            *acc = acc.wrapping_add(scalar.wrapping_mul(b)) & self.mask;
        }
    }
    #[inline]
    fn reduce_mul_add_slice_to(self, a: &[T], b: &[T], c: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(a.len(), c.len());
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (b_chunks, b_rem) = T::simd_as_chunks(b);
        let (c_chunks, c_rem) = T::simd_as_chunks(c);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for (((ac, bc), cc), oc) in a_chunks.iter().zip(b_chunks).zip(c_chunks).zip(o_chunks) {
            let av = T::SimdT::from_array(*ac);
            let bv = T::SimdT::from_array(*bc);
            let cv = T::SimdT::from_array(*cc);
            *oc = ((av * bv + cv) & mask).to_array();
        }

        for (((&a, &b), &c), o) in a_rem.iter().zip(b_rem).zip(c_rem).zip(o_rem) {
            *o = a.wrapping_mul(b).wrapping_add(c) & self.mask;
        }
    }
    #[inline]
    fn reduce_mul_scalar_add_slice_to(self, a: &[T], scalar: T, c: &[T], output: &mut [T]) {
        debug_assert_eq!(a.len(), c.len());
        debug_assert_eq!(a.len(), output.len());

        let mask = T::SimdT::splat(self.mask);
        let s = T::SimdT::splat(scalar);

        let (a_chunks, a_rem) = T::simd_as_chunks(a);
        let (c_chunks, c_rem) = T::simd_as_chunks(c);
        let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

        for ((ac, cc), oc) in a_chunks.iter().zip(c_chunks).zip(o_chunks) {
            let av = T::SimdT::from_array(*ac);
            let cv = T::SimdT::from_array(*cc);
            *oc = ((av * s + cv) & mask).to_array();
        }

        for ((&a, &c), o) in a_rem.iter().zip(c_rem).zip(o_rem) {
            *o = scalar.wrapping_mul(a).wrapping_add(c) & self.mask;
        }
    }
}

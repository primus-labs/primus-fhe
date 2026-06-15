use primus_integer::{SimdArray, SimdUnsignedInteger};
use primus_reduce::{Modulus, prelude::*};

use crate::common::compact;

#[inline]
pub fn lazy_reduce_mul_slice_assign<T, M, SM>(modulus: M, a: &mut [T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMul<T, Output = T>,
    SM: Copy + LazyReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());

    let sm: SM = modulus.into();

    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);

    for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *ac = sm.lazy_reduce_mul(av, bv).to_array();
    }

    for (a, &b) in a_rem.iter_mut().zip(b_rem) {
        *a = modulus.lazy_reduce_mul(*a, b)
    }
}

#[inline]
pub fn lazy_reduce_mul_slice_to<T, M, SM>(modulus: M, a: &[T], b: &[T], output: &mut [T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMul<T, Output = T>,
    SM: Copy + LazyReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *oc = sm.lazy_reduce_mul(av, bv).to_array();
    }

    for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
        *o = modulus.lazy_reduce_mul(a, b)
    }
}

#[inline]
pub fn lazy_reduce_mul_scalar_slice_assign<T, M, SM>(modulus: M, a: &mut [T], scalar: T)
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMul<T, Output = T>,
    SM: Copy + LazyReduceMul<T::SimdT, Output = T::SimdT>,
{
    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);
    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    for ac in a_chunks {
        let av = T::SimdT::from_array(*ac);
        *ac = sm.lazy_reduce_mul(av, sv).to_array();
    }

    for a in a_rem {
        *a = modulus.lazy_reduce_mul(*a, scalar)
    }
}

#[inline]
pub fn lazy_reduce_mul_scalar_slice_to<T, M, SM>(modulus: M, a: &[T], scalar: T, output: &mut [T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMul<T, Output = T>,
    SM: Copy + LazyReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), output.len());
    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for (ac, oc) in a_chunks.iter().zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        *oc = sm.lazy_reduce_mul(av, sv).to_array();
    }

    for (&a, o) in a_rem.iter().zip(o_rem) {
        *o = modulus.lazy_reduce_mul(a, scalar)
    }
}

#[inline]
pub fn lazy_reduce_add_mul_slice_assign<T, M, SM>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMulAdd<T, Output = T>,
    SM: Copy + LazyReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm: SM = modulus.into();
    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *accc = sm.lazy_reduce_mul_add(av, bv, accv).to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        *acc = modulus.lazy_reduce_mul_add(a, b, *acc)
    }
}

#[inline]
pub fn lazy_reduce_sub_mul_slice_assign<T, M, SM>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Modulus<ValueT = T> + Into<SM> + LazyReduceMulAdd<T, Output = T>,
    SM: Copy + LazyReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());

    let sm: SM = modulus.into();
    let m = unsafe { modulus.value_unchecked() };
    let mv = T::SimdT::splat(m);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);

    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let neg_bv = compact::simd::reduce_neg::<T>(mv, bv);
        *accc = sm.lazy_reduce_mul_add(av, neg_bv, accv).to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        let neg_b = compact::reduce_neg(m, b);
        *acc = modulus.lazy_reduce_mul_add(a, neg_b, *acc);
    }
}

#[inline]
pub fn lazy_reduce_mul_add_slice_to<T, M, SM>(
    modulus: M,
    a: &[T],
    b: &[T],
    c: &[T],
    output: &mut [T],
) where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMulAdd<T, Output = T>,
    SM: Copy + LazyReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for (((ac, bc), cc), oc) in a_chunks.iter().zip(b_chunks).zip(c_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.lazy_reduce_mul_add(av, bv, cv).to_array();
    }

    for (((&a, &b), &c), o) in a_rem.iter().zip(b_rem).zip(c_rem).zip(o_rem) {
        *o = modulus.lazy_reduce_mul_add(a, b, c)
    }
}

#[inline]
pub fn lazy_reduce_mul_scalar_add_slice_to<T, M, SM>(
    modulus: M,
    a: &[T],
    scalar: T,
    c: &[T],
    output: &mut [T],
) where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMulAdd<T, Output = T>,
    SM: Copy + LazyReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for ((ac, cc), oc) in a_chunks.iter().zip(c_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.lazy_reduce_mul_add(av, sv, cv).to_array();
    }

    for ((&b, &c), o) in a_rem.iter().zip(c_rem).zip(o_rem) {
        *o = modulus.lazy_reduce_mul_add(b, scalar, c)
    }
}

#[inline]
pub fn lazy_reduce_add_mul_scalar_slice_assign<T, M, SM>(
    modulus: M,
    acc: &mut [T],
    b: &[T],
    scalar: T,
) where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + LazyReduceMulAdd<T, Output = T>,
    SM: Copy + LazyReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), b.len());

    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);

    for (accc, bc) in acc_chunks.iter_mut().zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let bv = T::SimdT::from_array(*bc);
        *accc = sm.lazy_reduce_mul_add(sv, bv, accv).to_array();
    }

    for (acc, &b) in acc_rem.iter_mut().zip(b_rem) {
        *acc = modulus.lazy_reduce_mul_add(scalar, b, *acc)
    }
}

#[inline]
pub fn reduce_mul_slice_assign<T, M, SM>(modulus: M, a: &mut [T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMul<T, Output = T>,
    SM: Copy + ReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());
    let sm: SM = modulus.into();
    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for (ac, bc) in a_chunks.iter_mut().zip(b_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *ac = sm.reduce_mul(av, bv).to_array();
    }

    for (a, &b) in a_rem.iter_mut().zip(b_rem) {
        *a = modulus.reduce_mul(*a, b)
    }
}

#[inline]
pub fn reduce_mul_slice_to<T, M, SM>(modulus: M, a: &[T], b: &[T], output: &mut [T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMul<T, Output = T>,
    SM: Copy + ReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let sm: SM = modulus.into();
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((ac, bc), oc) in a_chunks.iter().zip(b_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *oc = sm.reduce_mul(av, bv).to_array();
    }

    for ((&a, &b), o) in a_rem.iter().zip(b_rem).zip(o_rem) {
        *o = modulus.reduce_mul(a, b)
    }
}

#[inline]
pub fn reduce_mul_scalar_slice_assign<T, M, SM>(modulus: M, a: &mut [T], scalar: T)
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMul<T, Output = T>,
    SM: Copy + ReduceMul<T::SimdT, Output = T::SimdT>,
{
    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);

    for ac in a_chunks {
        let av = T::SimdT::from_array(*ac);
        *ac = sm.reduce_mul(av, sv).to_array();
    }

    for a in a_rem {
        *a = modulus.reduce_mul(*a, scalar)
    }
}

#[inline]
pub fn reduce_mul_scalar_slice_to<T, M, SM>(modulus: M, a: &[T], scalar: T, output: &mut [T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMul<T, Output = T>,
    SM: Copy + ReduceMul<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for (ac, oc) in a_chunks.iter().zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        *oc = sm.reduce_mul(av, sv).to_array();
    }

    for (&a, o) in a_rem.iter().zip(o_rem) {
        *o = modulus.reduce_mul(a, scalar)
    }
}

#[inline]
pub fn reduce_add_mul_slice_assign<T, M, SM>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMulAdd<T, Output = T>,
    SM: Copy + ReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm: SM = modulus.into();
    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        *accc = sm.reduce_mul_add(av, bv, accv).to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        *acc = modulus.reduce_mul_add(a, b, *acc)
    }
}

#[inline]
pub fn reduce_sub_mul_slice_assign<T, M, SM>(modulus: M, acc: &mut [T], a: &[T], b: &[T])
where
    T: SimdUnsignedInteger,
    M: Copy + Modulus<ValueT = T> + Into<SM> + ReduceMulAdd<T, Output = T>,
    SM: Copy + ReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());

    let sm: SM = modulus.into();
    let m = unsafe { modulus.value_unchecked() };
    let mv = T::SimdT::splat(m);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);

    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let neg_bv = compact::simd::reduce_neg::<T>(mv, bv);
        *accc = sm.reduce_mul_add(av, neg_bv, accv).to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        let neg_b = compact::reduce_neg(m, b);
        *acc = modulus.reduce_mul_add(a, neg_b, *acc);
    }
}

#[inline]
pub fn reduce_mul_add_slice_to<T, M, SM>(modulus: M, a: &[T], b: &[T], c: &[T], output: &mut [T])
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMulAdd<T, Output = T>,
    SM: Copy + ReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for (((ac, bc), cc), oc) in a_chunks.iter().zip(b_chunks).zip(c_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.reduce_mul_add(av, bv, cv).to_array();
    }

    for (((&a, &b), &c), o) in a_rem.iter().zip(b_rem).zip(c_rem).zip(o_rem) {
        *o = modulus.reduce_mul_add(a, b, c)
    }
}

#[inline]
pub fn reduce_mul_scalar_add_slice_to<T, M, SM>(
    modulus: M,
    a: &[T],
    scalar: T,
    c: &[T],
    output: &mut [T],
) where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMulAdd<T, Output = T>,
    SM: Copy + ReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());

    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);

    for ((ac, cc), oc) in a_chunks.iter().zip(c_chunks).zip(o_chunks) {
        let av = T::SimdT::from_array(*ac);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.reduce_mul_add(av, sv, cv).to_array();
    }

    for ((&a, &c), o) in a_rem.iter().zip(c_rem).zip(o_rem) {
        *o = modulus.reduce_mul_add(a, scalar, c)
    }
}

#[inline]
pub fn reduce_add_mul_scalar_slice_assign<T, M, SM>(modulus: M, acc: &mut [T], b: &[T], scalar: T)
where
    T: SimdUnsignedInteger,
    M: Copy + Into<SM> + ReduceMulAdd<T, Output = T>,
    SM: Copy + ReduceMulAdd<T::SimdT, Output = T::SimdT>,
{
    debug_assert_eq!(acc.len(), b.len());

    let sm: SM = modulus.into();
    let sv = T::SimdT::splat(scalar);

    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);

    for (accc, bc) in acc_chunks.iter_mut().zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let bv = T::SimdT::from_array(*bc);
        *accc = sm.reduce_mul_add(sv, bv, accv).to_array();
    }

    for (acc, &b) in acc_rem.iter_mut().zip(b_rem) {
        *acc = modulus.reduce_mul_add(scalar, b, *acc)
    }
}

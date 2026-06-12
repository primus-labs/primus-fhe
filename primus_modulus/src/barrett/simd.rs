use primus_integer::{CarryingAdd, CarryingMul, SimdArray, SimdUnsignedInteger, WideningMul};
use primus_reduce::prelude::*;

use super::BarrettModulus;

use crate::common::compact::{simd, slice};

/// A modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Debug, Clone, Copy)]
pub struct SimdBarrettModulus<T: SimdUnsignedInteger> {
    value: T::SimdT,
    ratio: [T::SimdT; 2],
}

impl<T: SimdUnsignedInteger> SimdBarrettModulus<T> {
    #[inline]
    pub fn lazy_reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        let ah = lo.widening_mul_hw(self.ratio[0]);

        let b = lo.carrying_mul(self.ratio[1], ah);
        let c = hi.widening_mul(self.ratio[0]);

        let d = hi * self.ratio[1];

        let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

        let q = d + bch;

        // Step 2.
        lo - (q * self.value)
    }

    #[inline]
    pub fn reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        simd::simd_reduce_once::<T>(self.lazy_reduce_wide(lo, hi), self.value)
    }
}

impl<T: SimdUnsignedInteger> From<BarrettModulus<T>> for SimdBarrettModulus<T> {
    #[inline]
    fn from(modulus: BarrettModulus<T>) -> Self {
        let ratio = modulus.ratio();
        Self {
            value: T::SimdT::splat(modulus.value()),
            ratio: [T::SimdT::splat(ratio[0]), T::SimdT::splat(ratio[1])],
        }
    }
}

impl<T: SimdUnsignedInteger> LazyReduce<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce(self, value: T::SimdT) -> Self::Output {
        let tmp = value.widening_mul_hw(self.ratio[0]); // tmp1
        let q = value.carrying_mul_hw(self.ratio[1], tmp); // q₃

        // Step 2.
        value - (q * self.value) // r = r₁ - r₂
    }
}

impl<T: SimdUnsignedInteger> LazyReduceAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_assign(self, value: &mut T::SimdT) {
        *value = self.lazy_reduce(*value);
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMul<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce_mul(self, a: T::SimdT, b: T::SimdT) -> Self::Output {
        let (lo, hi) = a.widening_mul(b);
        self.lazy_reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_assign(self, a: &mut T::SimdT, b: T::SimdT) {
        let (lo, hi) = a.widening_mul(b);
        *a = self.lazy_reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAdd<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce_mul_add(self, a: T::SimdT, b: T::SimdT, c: T::SimdT) -> Self::Output {
        let (lo, hi) = a.carrying_mul(b, c);
        self.lazy_reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAddAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_add_assign(self, a: &mut T::SimdT, b: T::SimdT, c: T::SimdT) {
        let (lo, hi) = a.carrying_mul(b, c);
        *a = self.lazy_reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> Reduce<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce(self, value: T::SimdT) -> Self::Output {
        simd::simd_reduce_once::<T>(self.lazy_reduce(value), self.value)
    }
}

impl<T: SimdUnsignedInteger> ReduceAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_assign(self, value: &mut T::SimdT) {
        *value = self.reduce(*value);
    }
}

impl<T: SimdUnsignedInteger> ReduceMul<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce_mul(self, a: T::SimdT, b: T::SimdT) -> Self::Output {
        let (lo, hi) = a.widening_mul(b);
        self.reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_mul_assign(self, a: &mut T::SimdT, b: T::SimdT) {
        let (lo, hi) = a.widening_mul(b);
        *a = self.reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAdd<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce_mul_add(self, a: T::SimdT, b: T::SimdT, c: T::SimdT) -> Self::Output {
        let (lo, hi) = a.carrying_mul(b, c);
        self.reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAddAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_mul_add_assign(self, a: &mut T::SimdT, b: T::SimdT, c: T::SimdT) {
        let (lo, hi) = a.carrying_mul(b, c);
        *a = self.reduce_wide(lo, hi);
    }
}

// ===========================================================================
// SIMD slice kernels.
// ===========================================================================

#[inline]
pub fn lazy_reduce_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &mut [T],
    b: &[T],
) {
    debug_assert_eq!(a.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn lazy_reduce_mul_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    b: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn lazy_reduce_scalar_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &mut [T],
    scalar: T,
) {
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn lazy_reduce_scalar_mul_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    scalar: T,
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &mut [T],
    b: &[T],
) {
    debug_assert_eq!(a.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_mul_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    b: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_scalar_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &mut [T],
    scalar: T,
) {
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_scalar_mul_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    scalar: T,
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_add_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    a: &[T],
    b: &[T],
) {
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn reduce_add_scalar_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    scalar: T,
    b: &[T],
) {
    debug_assert_eq!(acc.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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

#[inline]
pub fn reduce_sub_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    a: &[T],
    b: &[T],
) {
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
    let m = T::SimdT::splat(modulus.value());
    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let prod = sm.reduce_mul(av, bv);
        *accc = simd::simd_reduce_sub::<T>(accv, prod, m).to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        let prod = modulus.reduce_mul(a, b);
        modulus.reduce_sub_assign(acc, prod);
    }
}

#[inline]
pub fn reduce_mul_add_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    b: &[T],
    c: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);

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
pub fn reduce_scalar_mul_add_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    scalar: T,
    b: &[T],
    c: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(b.len(), c.len());
    debug_assert_eq!(b.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
    let sv = T::SimdT::splat(scalar);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((bc, cc), oc) in b_chunks.iter().zip(c_chunks).zip(o_chunks) {
        let bv = T::SimdT::from_array(*bc);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.reduce_mul_add(sv, bv, cv).to_array();
    }

    for ((&b, &c), o) in b_rem.iter().zip(c_rem).zip(o_rem) {
        *o = modulus.reduce_mul_add(scalar, b, c)
    }
}

#[inline]
pub fn lazy_reduce_add_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    a: &[T],
    b: &[T],
) {
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn lazy_reduce_sub_mul_slice_assign<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    a: &[T],
    b: &[T],
) {
    debug_assert_eq!(acc.len(), a.len());
    debug_assert_eq!(acc.len(), b.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
    let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
    let (a_chunks, a_rem) = T::simd_as_chunks(a);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    for ((accc, ac), bc) in acc_chunks.iter_mut().zip(a_chunks).zip(b_chunks) {
        let accv = T::SimdT::from_array(*accc);
        let av = T::SimdT::from_array(*ac);
        let bv = T::SimdT::from_array(*bc);
        let prod = sm.reduce_mul(av, bv);
        let diff = accv + sm.value - prod;
        *accc = diff.to_array();
    }

    for ((acc, &a), &b) in acc_rem.iter_mut().zip(a_rem).zip(b_rem) {
        let prod = modulus.reduce_mul(a, b);
        *acc = acc.wrapping_add(modulus.value).wrapping_sub(prod);
    }
}

#[inline]
pub fn lazy_reduce_mul_add_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    b: &[T],
    c: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), c.len());
    debug_assert_eq!(a.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
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
pub fn lazy_reduce_scalar_mul_add_slice_to<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    scalar: T,
    b: &[T],
    c: &[T],
    output: &mut [T],
) {
    debug_assert_eq!(b.len(), c.len());
    debug_assert_eq!(b.len(), output.len());
    let sm = SimdBarrettModulus::<T>::from(modulus);
    let sv = T::SimdT::splat(scalar);
    let (b_chunks, b_rem) = T::simd_as_chunks(b);
    let (c_chunks, c_rem) = T::simd_as_chunks(c);
    let (o_chunks, o_rem) = T::simd_as_chunks_mut(output);
    for ((bc, cc), oc) in b_chunks.iter().zip(c_chunks).zip(o_chunks) {
        let bv = T::SimdT::from_array(*bc);
        let cv = T::SimdT::from_array(*cc);
        *oc = sm.lazy_reduce_mul_add(sv, bv, cv).to_array();
    }

    for ((&b, &c), o) in b_rem.iter().zip(c_rem).zip(o_rem) {
        *o = modulus.lazy_reduce_mul_add(scalar, b, c)
    }
}

// ---------------------------------------------------------------------------
// SIMD dot_product
//
// Outer chunk size = `K * N`, where `K = super::slice::DOT_PRODUCT_INNER_CHUNK`
// (currently 16). Inside each outer chunk we accumulate `K` SIMD widening
// products into a `[T::SimdT; 2]` double-word per lane, then collapse the
// double-word back into a single SIMD word in `[0, m)` via Barrett + the
// `min(v, v - m)` reduce_once trick. Cross-chunk accumulation stays in `[0, m)`
// lane-wise via `simd_reduce_add`, so the running SIMD accumulator never grows.
// After the chunked loop, a horizontal modular sum collapses the N lanes to a
// scalar, and any tail shorter than `K * N` is handled by the scalar helper.
//
// Hi-limb safety: each scalar widening product has `hi < m^2 / 2^BITS`, and the
// lo-limb's running sum can carry at most `K - 1` extra units into hi. With
// `m < 2^(BITS - 1)` enforced by `BarrettModulus::new` and `K ≤ 16`, both
// limbs stay strictly below `2^BITS` — identical bound to the scalar path.
// ---------------------------------------------------------------------------

#[inline]
pub fn reduce_dot_product<T: SimdUnsignedInteger>(
    modulus: BarrettModulus<T>,
    a: &[T],
    b: &[T],
) -> T {
    debug_assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

    let k = 16;
    let outer = k * T::LANE_COUNT;

    let sm = SimdBarrettModulus::<T>::from(modulus);
    let m_simd = sm.value;

    let mut total_acc = T::SimdT::splat(T::ZERO);

    let mut a_outer = a.chunks_exact(outer);
    let mut b_outer = b.chunks_exact(outer);

    for (a_chunk, b_chunk) in (&mut a_outer).zip(&mut b_outer) {
        // Each outer chunk is exactly `K * N` elements, so the inner
        // `as_chunks::<N>` always splits into `K` lane-wide subchunks with
        // an empty tail.
        let (a_lanes, _) = T::simd_as_chunks(a_chunk);
        let (b_lanes, _) = T::simd_as_chunks(b_chunk);
        let mut c = [T::SimdT::splat(T::ZERO); 2];
        for (a_n, b_n) in a_lanes.iter().zip(b_lanes) {
            let av = T::SimdT::from_array(*a_n);
            let bv = T::SimdT::from_array(*b_n);
            simd::simd_multiply_add::<T>(&mut c, av, bv);
        }
        let r = simd::simd_reduce_once::<T>(sm.lazy_reduce_wide(c[0], c[1]), sm.value);
        total_acc = simd::simd_reduce_add::<T>(total_acc, r, m_simd);
    }

    let lanes = total_acc.to_array();
    let mut result = T::ZERO;
    for v in lanes {
        result = modulus.reduce_add(result, v);
    }

    let tail_result = slice::reduce_dot_product(modulus, a_outer.remainder(), b_outer.remainder());

    modulus.reduce_add(result, tail_result)
}

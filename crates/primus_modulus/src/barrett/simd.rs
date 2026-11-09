//! SIMD Barrett modulus implementation and dot-product helper.

use core::simd::cmp::SimdPartialOrd;

use primus_integer::{
    CarryingAdd, CarryingMul, FheUint, SimdArray, SimdInteger, SimdMaskArray, SimdUnsignedArray,
    SimdUnsignedInteger, WideningMul,
};
use primus_reduce::prelude::*;

use super::BarrettModulus;

use crate::common::compact;

/// A lane-wise Barrett context used by SIMD kernels.
///
/// It broadcasts a scalar modulus and its reciprocal to every SIMD lane. The
/// scalar modulus must satisfy `1 < value < 2^(T::BITS - 2)`.
#[derive(Debug, Clone, Copy)]
pub struct SimdBarrettModulus<T: SimdUnsignedInteger> {
    value: T::SimdT,
    ratio: [T::SimdT; 2],
}

impl<T: SimdUnsignedInteger> SimdBarrettModulus<T> {
    /// Creates a [`SimdBarrettModulus<T>`] from precomputed parts.
    ///
    /// # Correctness
    ///
    /// `value` must satisfy `1 < value < 2^(T::BITS - 2)`, and `ratio` must be
    /// the little-endian limbs `[low, high]` of `floor(B² / value)`, where
    /// `B = 2^(T::BITS)`. Prefer converting a validated [`BarrettModulus`] when
    /// runtime construction is sufficient.
    #[must_use]
    pub fn from_parts(value: T, ratio: [T; 2]) -> Self {
        Self {
            value: T::SimdT::splat(value),
            ratio: [T::SimdT::splat(ratio[0]), T::SimdT::splat(ratio[1])],
        }
    }
}

impl<T: SimdUnsignedInteger> SimdBarrettModulus<T> {
    /// Lazily reduces a lane-wise 2-limb value `(hi * B + lo)` modulo this modulus.
    ///
    /// The result in every lane is in `[0, 2 * modulus)`.
    #[must_use]
    #[inline]
    pub fn lazy_reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        let ah = lo.widening_mul_hw(self.ratio[0]);

        let b = lo.carrying_mul(self.ratio[1], ah);
        let c = hi.widening_mul(self.ratio[0]);

        let d = hi * self.ratio[1];

        let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

        let q = d + bch;

        // Subtract the estimated multiple modulo `B` lane-wise.
        lo - (q * self.value)
    }

    /// Reduces a lane-wise 2-limb value `(hi * B + lo)` modulo this modulus.
    #[must_use]
    #[inline]
    pub fn reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        compact::simd::reduce_once::<T>(self.value, self.lazy_reduce_wide(lo, hi))
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
        let tmp = value.widening_mul_hw(self.ratio[0]);
        let q = value.carrying_mul_hw(self.ratio[1], tmp);

        value - (q * self.value)
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
        compact::simd::reduce_once::<T>(self.value, self.lazy_reduce(value))
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

// Each outer chunk contains `K = DOT_PRODUCT_INNER_CHUNK` SIMD vectors. Every
// lane accumulates `K` widening products, is reduced, and is then added to the
// running lane-wise residue. The final horizontal sum and scalar tail complete
// the dot product.
//
// Accumulator safety: each operand is below `2^(BITS - 2)`, even if it
// exceeds the destination modulus, so
// each product is less than `2^(2 * BITS - 4)`. With `K = 16`, their sum is
// less than `2^(2 * BITS)` and fits in the two-limb accumulator.
/// Computes the dot product of `a` and `b` modulo `modulus` using SIMD chunks.
///
/// # Correctness
///
/// Every operand is below `2^(T::BITS - 2)`; it may exceed the modulus.
/// The scalar context and its SIMD conversion must agree and satisfy
/// `1 < modulus < 2^(T::BITS - 2)`, with canonical two-limb reduction.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths.
#[must_use]
#[inline]
pub fn simd_reduce_dot_product<T: SimdUnsignedInteger, M>(modulus: M, a: &[T], b: &[T]) -> T
where
    M: Copy + Into<SimdBarrettModulus<T>> + ReduceAdd<T, Output = T> + Reduce<[T; 2], Output = T>,
{
    assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

    let outer = compact::DOT_PRODUCT_INNER_CHUNK * T::LANE_COUNT;

    // Below one complete SIMD accumulator chunk, setup and horizontal
    // reduction cost more than the scalar kernel.
    if a.len() < outer {
        return compact::slice::reduce_dot_product(modulus, a, b);
    }

    let sm: SimdBarrettModulus<T> = modulus.into();
    let mv = sm.value;

    let mut total_acc = T::SimdT::splat(T::ZERO);

    let mut a_outer = a.chunks_exact(outer);
    let mut b_outer = b.chunks_exact(outer);

    for (a_chunk, b_chunk) in (&mut a_outer).zip(&mut b_outer) {
        // An outer chunk contains exactly `K` full SIMD vectors.
        let (a_lanes, _) = T::simd_as_chunks(a_chunk);
        let (b_lanes, _) = T::simd_as_chunks(b_chunk);
        let mut c = [T::SimdT::splat(T::ZERO); 2];
        for (a_n, b_n) in a_lanes.iter().zip(b_lanes) {
            let av = T::SimdT::from_array(*a_n);
            let bv = T::SimdT::from_array(*b_n);
            compact::simd::multiply_add::<T>(&mut c, av, bv);
        }
        let r = compact::simd::reduce_once::<T>(mv, sm.lazy_reduce_wide(c[0], c[1]));
        total_acc = compact::simd::reduce_add::<T>(mv, total_acc, r);
    }

    let lanes = total_acc.to_array();
    let mut result = T::ZERO;
    for v in lanes {
        result = modulus.reduce_add(result, v);
    }

    let tail_result =
        compact::slice::reduce_dot_product(modulus, a_outer.remainder(), b_outer.remainder());

    modulus.reduce_add(result, tail_result)
}

/// Computes a mixed signed dot product with scalar/SIMD dispatch.
///
/// # Correctness
///
/// The scalar modulus and its SIMD conversion must agree and satisfy
/// `1 < q < 2^(T::BITS - 2)`. Inputs must satisfy
/// [`ReduceDotProductSigned::reduce_dot_product_signed`]'s range contracts.
/// The scalar context must implement canonical two-limb reduction.
///
/// # Panics
///
/// Panics if the slices have different lengths.
#[must_use]
#[inline]
pub fn simd_reduce_dot_product_signed<T: FheUint, M>(
    modulus: M,
    lhs: &[T],
    rhs: &[T::SignedInteger],
) -> T
where
    M: EncodeSigned<T>
        + Into<SimdBarrettModulus<T>>
        + ReduceAdd<T, Output = T>
        + ReduceAddAssign<T>
        + Reduce<[T; 2], Output = T>,
{
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "reduce_dot_product_signed: length mismatch"
    );
    let outer = compact::DOT_PRODUCT_INNER_CHUNK * T::LANE_COUNT;
    if lhs.len() < outer {
        return compact::slice::dot_product_signed(modulus, lhs, rhs);
    }
    let sm: SimdBarrettModulus<T> = modulus.into();
    let mv = sm.value;
    let signed_max = T::SimdT::splat(T::MAX >> 1u32);
    let mut total_acc = T::SimdT::splat(T::ZERO);
    let mut lhs_outer = lhs.chunks_exact(outer);
    let mut rhs_outer = rhs.chunks_exact(outer);
    for (lhs, rhs) in (&mut lhs_outer).zip(&mut rhs_outer) {
        let (lhs_lanes, _) = T::simd_as_chunks(lhs);
        let (rhs_lanes, _) = T::SignedInteger::simd_as_chunks(rhs);
        let mut acc = [T::SimdT::splat(T::ZERO); 2];
        for (lhs, rhs) in lhs_lanes.iter().zip(rhs_lanes) {
            let a = T::SimdT::from_array(*lhs);
            let s = <T::SignedInteger as SimdInteger>::SimdT::from_array(*rhs);
            let bits = T::simd_cast_from_signed(s);
            // Only negative lanes add q. Wrapping addition gives q + s in
            // [0, q), keeping the unsigned kernel's 16-product bound intact.
            let encoded = bits.simd_gt(signed_max).select(bits + mv, bits);
            compact::simd::multiply_add::<T>(&mut acc, a, encoded);
        }
        let block = compact::simd::reduce_once::<T>(mv, sm.lazy_reduce_wide(acc[0], acc[1]));
        total_acc = compact::simd::reduce_add::<T>(mv, total_acc, block);
    }
    let mut result = T::ZERO;
    for lane in total_acc.to_array() {
        result = modulus.reduce_add(result, lane);
    }
    let tail =
        compact::slice::dot_product_signed(modulus, lhs_outer.remainder(), rhs_outer.remainder());
    modulus.reduce_add(result, tail)
}

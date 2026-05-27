//! SIMD abstractions for unsigned integer types.
//!
//! This module provides traits and blanket implementations that extend the
//! scalar [`UnsignedInteger`] operations to SIMD
//! vectors when the `simd` features are enabled.
//!
//! [`SimdUnsignedInteger`] marks unsigned integer types that can serve as
//! SIMD lane elements. [`SimdArray`] extends [`Simd`] vectors with the
//! arithmetic and comparison capabilities required by higher-level crates.
//! [`SimdMaskArray`] provides the corresponding mask operations.

use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::*,
    simd::{
        Mask, MaskElement, Select, Simd, SimdCast, SimdElement,
        cmp::{SimdOrd, SimdPartialEq, SimdPartialOrd},
        num::SimdUint,
    },
};

use crate::{BorrowingSub, CarryingAdd, CarryingMul, WideningMul};

use super::UnsignedInteger;

/// Native SIMD vector width in bits.
#[cfg(target_feature = "avx512f")]
pub const VECTOR_BITS: usize = 512;

/// Native SIMD vector width in bits.
#[cfg(not(target_feature = "avx512f"))]
pub const VECTOR_BITS: usize = 256;

/// Unsigned integer types that can serve as SIMD lane elements.
pub trait SimdUnsignedInteger: UnsignedInteger + SimdElement + SimdCast {
    /// SIMD vector type using this scalar's default lane count.
    ///
    /// Generic code should prefer this associated type over spelling
    /// `Simd<Self, { Self::LANE_COUNT }>` directly, because const expressions
    /// involving type parameters still require unstable `generic_const_exprs`.
    type SimdT: SimdArray<Self>;

    /// Signed SIMD vector with the same lane count as [`Self::SimdT`].
    ///
    /// This is the vector representation used when converting masks to and
    /// from integer lanes. A true lane is represented as `-1`, and a false lane
    /// as `0`, matching `portable_simd` mask conversion semantics.
    type SignedSimdT;

    /// SIMD mask type matching [`Self::SimdT`].
    ///
    /// The mask element type is the signed mask backing type associated with
    /// this scalar through [`SimdElement::Mask`].
    type MaskT: SimdMaskArray<Self, <Self as SimdElement>::Mask>;

    /// Array type containing exactly one default SIMD chunk of scalar lanes.
    ///
    /// This is normally `[Self; Self::LANE_COUNT]`, exposed as an associated
    /// type so generic code can work with SIMD-sized chunks without naming the
    /// const expression directly.
    type Array: Copy;

    /// Boolean selector array matching [`Self::MaskT`].
    ///
    /// This is normally `[bool; Self::LANE_COUNT]` and is used for converting
    /// masks to and from their lane-wise boolean representation.
    type Selector: Copy;

    /// The number of lanes in a SIMD vector for this element type at the
    /// target's preferred vector width.
    const LANE_COUNT: usize;

    /// Splits a slice into default SIMD-sized chunks and a scalar tail.
    ///
    /// The returned chunk slice is backed by [`Self::Array`], so callers can
    /// construct [`Self::SimdT`] values without writing the lane-count const
    /// expression at the call site.
    fn simd_as_chunks(slice: &[Self]) -> (&[Self::Array], &[Self]);

    /// Splits a mutable slice into default SIMD-sized chunks and a scalar tail.
    ///
    /// This is the mutable counterpart of [`Self::simd_as_chunks`], intended
    /// for kernels that write whole SIMD chunks and then handle the remaining
    /// scalar lanes separately.
    fn simd_as_chunks_mut(slice: &mut [Self]) -> (&mut [Self::Array], &mut [Self]);
}

macro_rules! impl_simd_unsigned_integer {
    ($($t:ty)*) => ($(
        impl SimdUnsignedInteger for $t {
            const LANE_COUNT: usize = VECTOR_BITS / <$t>::BITS as usize;
            type SimdT = Simd<$t, {Self::LANE_COUNT}>;
            type SignedSimdT = Simd<<$t as SimdElement>::Mask, {Self::LANE_COUNT}>;
            type MaskT = Mask<<$t as SimdElement>::Mask, {Self::LANE_COUNT}>;
            type Array = [$t; {Self::LANE_COUNT}];
            type Selector = [bool; {Self::LANE_COUNT}];

            #[inline]
            fn simd_as_chunks(slice: &[Self]) -> (&[Self::Array], &[Self]) {
                slice.as_chunks::<{Self::LANE_COUNT}>()
            }

            #[inline]
            fn simd_as_chunks_mut(slice: &mut [Self]) -> (&mut [Self::Array], &mut [Self]) {
                slice.as_chunks_mut::<{Self::LANE_COUNT}>()
            }
        }
    )*)
}

impl_simd_unsigned_integer! {u8 u16 u32 u64 usize}

/// SIMD vector of `N` elements of type `T`, extending [`Simd`] with the
/// arithmetic and comparison capabilities required by higher-level crates.
pub trait SimdArray<T: SimdUnsignedInteger>
where
    Self: Send + Sync + Clone + Copy + Default,
    Self: PartialEq + PartialOrd + Eq + Ord,
    Self: Debug,
    Self: From<T::SimdT> + Into<T::SimdT>,
    Self: From<<T as SimdUnsignedInteger>::Array> + Into<<T as SimdUnsignedInteger>::Array>,
    Self: AsRef<<T as SimdUnsignedInteger>::Array> + AsMut<<T as SimdUnsignedInteger>::Array>,
    Self:
        SimdPartialEq<Mask: SimdMaskArray<T, <T as SimdElement>::Mask>> + SimdPartialOrd + SimdOrd,
    Self: Product<Self> + Sum<Self>,
    for<'a> Self: Product<&'a Self> + Sum<&'a Self>,
    Self: Index<usize, Output = T> + IndexMut<usize, Output = T>,
    Self: Add<Output = Self> + AddAssign,
    Self: Sub<Output = Self> + SubAssign,
    Self: Mul<Output = Self> + MulAssign,
    Self: Div<Output = Self> + DivAssign,
    Self: Rem<Output = Self> + RemAssign,
    Self: BitAnd<Output = Self> + BitAndAssign,
    Self: BitOr<Output = Self> + BitOrAssign,
    Self: BitXor<Output = Self> + BitXorAssign,
    Self: Not<Output = Self>,
    for<'a> Self: Add<&'a Self, Output = Self> + AddAssign<&'a Self>,
    for<'a> Self: Sub<&'a Self, Output = Self> + SubAssign<&'a Self>,
    for<'a> Self: Mul<&'a Self, Output = Self> + MulAssign<&'a Self>,
    for<'a> Self: Div<&'a Self, Output = Self> + DivAssign<&'a Self>,
    for<'a> Self: Rem<&'a Self, Output = Self> + RemAssign<&'a Self>,
    for<'a> Self: BitAnd<&'a Self, Output = Self> + BitAndAssign<&'a Self>,
    for<'a> Self: BitOr<&'a Self, Output = Self> + BitOrAssign<&'a Self>,
    for<'a> Self: BitXor<&'a Self, Output = Self> + BitXorAssign<&'a Self>,
    Self: SimdUint<Scalar = T>,
    Self: CarryingAdd<CarryT = Self::Mask>
        + BorrowingSub<BorrowT = Self::Mask>
        + WideningMul
        + CarryingMul,
{
    /// Returns a tuple of the sum along with a boolean indicating whether an arithmetic overflow would occur.
    /// If an overflow would have occurred then the wrapped value is returned.
    fn overflowing_add(self, rhs: Self) -> (Self, Self::Mask) {
        let a = self + rhs;
        (a, a.simd_lt(self))
    }
}

macro_rules! impl_simd_array {
    ($($t:ty)*) => ($(
        impl SimdArray<$t> for Simd<$t, {<$t>::LANE_COUNT}>  {}
    )*)
}

impl_simd_array! {u8 u16 u32 u64 usize}

/// SIMD mask of `N` elements, providing bitwise and selection operations.
#[allow(clippy::len_without_is_empty)]
pub trait SimdMaskArray<U: SimdUnsignedInteger, T: MaskElement>
where
    Self: Send + Sync + Clone + Copy + Default,
    Self: PartialEq + PartialOrd,
    Self: Debug,
    Self: Select<U::SimdT>,
    Self: From<U::Selector> + Into<U::Selector>,
    Self: SimdPartialEq<Mask = Self> + SimdPartialOrd + SimdOrd,
    Self: BitAnd<Output = Self> + BitAndAssign + BitAnd<bool, Output = Self> + BitAndAssign<bool>,
    Self: BitOr<Output = Self> + BitOrAssign + BitOr<bool, Output = Self> + BitOrAssign<bool>,
    Self: BitXor<Output = Self> + BitXorAssign + BitXor<bool, Output = Self> + BitXorAssign<bool>,
    Self: Not<Output = Self>,
{
    /// Get the number of lanes in this vector.
    #[must_use]
    #[inline]
    fn len(&self) -> usize {
        U::LANE_COUNT
    }

    /// Choose elements from two vectors.
    ///
    /// For each element in the mask, choose the corresponding element from `true_values` if
    /// that element mask is true, and `false_values` if that element mask is false.
    ///
    /// # Examples
    /// ```ignore
    /// # #![feature(portable_simd)]
    /// # use core::simd::{Simd, Mask};
    /// let a = Simd::from_array([0, 1, 2, 3]);
    /// let b = Simd::from_array([4, 5, 6, 7]);
    /// let mask = Mask::from_array([true, false, false, true]);
    /// let c = mask.select(a, b);
    /// assert_eq!(c.to_array(), [0, 5, 6, 3]);
    /// ```
    #[must_use = "method returns a new vector and does not mutate the original inputs"]
    fn select(self, true_values: U::SimdT, false_values: U::SimdT) -> U::SimdT;

    /// Constructs a mask by setting all elements to the given value.
    fn splat(value: bool) -> Self;

    /// Converts an array of bools to a SIMD mask.
    fn from_array(array: U::Selector) -> Self;

    /// Converts a SIMD mask to an array of bools.
    fn to_array(self) -> U::Selector;

    /// Converts a vector of integers to a mask, where 0 represents `false` and -1
    /// represents `true`.
    ///
    /// # Panics
    /// Panics if any element is not 0 or -1.
    #[must_use = "method returns a new mask and does not mutate the original value"]
    #[track_caller]
    fn from_simd(value: U::SignedSimdT) -> Self;

    /// Converts the mask to a vector of integers, where 0 represents `false` and -1
    /// represents `true`.
    #[must_use = "method returns a new vector and does not mutate the original value"]
    fn to_simd(self) -> U::SignedSimdT;

    /// Returns true if any element is set, or false otherwise.
    #[must_use = "method returns a new bool and does not mutate the original value"]
    fn any(self) -> bool;

    /// Returns true if all elements are set, or false otherwise.
    #[must_use = "method returns a new bool and does not mutate the original value"]
    fn all(self) -> bool;
}

macro_rules! impl_mask_array {
    ($t:ty, $u:ty) => {
        impl SimdMaskArray<$u, $t> for Mask<$t, { <$u>::LANE_COUNT }> {
            #[inline]
            fn select(
                self,
                true_values: Simd<$u, { <$u>::LANE_COUNT }>,
                false_values: Simd<$u, { <$u>::LANE_COUNT }>,
            ) -> Simd<$u, { <$u>::LANE_COUNT }> {
                Select::select(self, true_values, false_values)
            }

            #[inline]
            fn splat(value: bool) -> Self {
                Self::splat(value)
            }

            #[inline]
            fn from_array(array: [bool; { <$u>::LANE_COUNT }]) -> Self {
                Self::from_array(array)
            }

            #[inline]
            fn to_array(self) -> [bool; { <$u>::LANE_COUNT }] {
                self.to_array()
            }

            #[inline]
            fn from_simd(value: Simd<$t, { <$u>::LANE_COUNT }>) -> Self {
                Self::from_simd(value)
            }

            #[inline]
            fn to_simd(self) -> Simd<$t, { <$u>::LANE_COUNT }> {
                self.to_simd()
            }

            #[inline]
            fn any(self) -> bool {
                self.any()
            }

            #[inline]
            fn all(self) -> bool {
                self.all()
            }
        }
    };
}

impl_mask_array! {i8, u8}
impl_mask_array! {i16, u16}
impl_mask_array! {i32, u32}
impl_mask_array! {i64, u64}
impl_mask_array! {isize, usize}

#[cfg(test)]
mod tests {
    use crate::AsInto;

    use super::*;

    fn test_add<T: SimdUnsignedInteger>() {
        let a: Vec<T> = (0..1027).map(|a| a.as_into()).collect();
        let b: Vec<T> = (0..1027).rev().map(|b| b.as_into()).collect();
        let mut c: Vec<T> = vec![T::ZERO; 1024];

        let (a_chunks, a_rem) = T::simd_as_chunks(&a);
        let (b_chunks, b_rem) = T::simd_as_chunks(&b);
        let (c_chunks, c_rem) = T::simd_as_chunks_mut(&mut c);
        for ((&ac, &bc), cc) in a_chunks.iter().zip(b_chunks).zip(c_chunks) {
            let av = T::SimdT::from(ac);
            let bv = T::SimdT::from(bc);
            *cc = (av + bv).into();
        }

        for ((&a, &b), c) in a_rem.iter().zip(b_rem).zip(c_rem) {
            *c = a + b;
        }

        assert!(c.iter().copied().all(|a| a == 1026.as_into()));
    }

    #[test]
    fn test_simd_traits() {
        test_add::<u16>();
        test_add::<u32>();
        test_add::<u64>();
        test_add::<usize>();
    }
}

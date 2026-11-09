//! SIMD abstractions for integer types.
//!
//! [`SimdInteger`], [`SimdArray`], and [`SimdMaskArray`] provide the common
//! vector layout, arithmetic, comparison, and mask operations shared by signed
//! and unsigned integers. [`SimdUnsignedInteger`] and [`SimdUnsignedArray`]
//! add the carrying and widening operations required by unsigned word
//! arithmetic.

use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::*,
    simd::{
        Mask, Select, Simd, SimdCast, SimdElement,
        cmp::{SimdOrd, SimdPartialEq, SimdPartialOrd},
        num::SimdUint,
    },
};

use crate::{BorrowingSub, CarryingAdd, CarryingMul, Integer, UnsignedInteger, WideningMul};

/// Default SIMD vector width selected by this crate, in bits.
#[cfg(target_feature = "avx512f")]
pub const VECTOR_BITS: u32 = 512;

/// Default SIMD vector width selected by this crate, in bits.
#[cfg(not(target_feature = "avx512f"))]
pub const VECTOR_BITS: u32 = 256;

/// Fixed-size array of scalar lanes used to exchange data with SIMD vectors.
pub trait LaneArray<T: Integer>: Copy + AsRef<[T]> + AsMut<[T]> + IntoIterator<Item = T> {
    /// Builds a lane array with every lane set to zero.
    #[must_use]
    #[inline]
    fn zero() -> Self {
        Self::splat(T::ZERO)
    }

    /// Builds a lane array with every lane set to `value`.
    #[must_use]
    fn splat(value: T) -> Self;

    /// Builds a lane array by calling `f` once for each lane index.
    #[must_use]
    fn from_fn<F: FnMut(usize) -> T>(f: F) -> Self;

    /// Maps each lane to a new array without exposing lane indices.
    #[must_use]
    fn map(self, f: impl FnMut(T) -> T) -> Self;

    /// Builds a lane array from a slice with the same number of elements.
    #[must_use]
    fn try_from_slice(slice: &[T]) -> Option<Self>;
}

impl<T: Integer, const N: usize> LaneArray<T> for [T; N] {
    #[inline]
    fn splat(value: T) -> Self {
        [value; N]
    }

    #[inline]
    fn from_fn<F: FnMut(usize) -> T>(f: F) -> Self {
        core::array::from_fn(f)
    }

    #[inline]
    fn map(self, f: impl FnMut(T) -> T) -> Self {
        self.map(f)
    }

    #[inline]
    fn try_from_slice(slice: &[T]) -> Option<Self> {
        let array: &[T; N] = slice.try_into().ok()?;
        Some(*array)
    }
}

/// Integer types that can serve as SIMD lane elements.
pub trait SimdInteger: Integer + SimdElement + SimdCast {
    /// The number of lanes in a SIMD vector for this element type at the
    /// target's preferred vector width.
    const LANE_COUNT: usize;

    /// Array type containing exactly one SIMD chunk of scalar lanes.
    ///
    /// This is normally `[Self; Self::LANE_COUNT]`, exposed as an associated
    /// type so generic code can work with SIMD-sized chunks without naming the
    /// const expression directly.
    type Array: LaneArray<Self>;

    /// Boolean selector array matching [`Self::MaskT`](Self::MaskT).
    ///
    /// This is normally `[bool; Self::LANE_COUNT]` and is used for converting
    /// masks to and from their lane-wise boolean representation.
    type Selector: Copy;

    /// SIMD vector type using this scalar's default lane count.
    ///
    /// Generic code should prefer this associated type over spelling
    /// `Simd<Self, { Self::LANE_COUNT }>` directly, because const expressions
    /// involving type parameters still require unstable `generic_const_exprs`.
    type SimdT: SimdArray<Self>;

    /// SIMD mask type matching [`Self::SimdT`].
    ///
    /// The mask element type is the signed mask backing type associated with
    /// this scalar through [`SimdElement::Mask`].
    type MaskT: SimdMaskArray<Self>;

    /// Integer SIMD vector used as the mask representation.
    ///
    /// A true lane is represented as `-1`, and a false lane as `0`, matching
    /// `portable_simd` mask conversion semantics.
    type MaskReprT;

    /// Splits a slice into default SIMD-sized chunks and a scalar tail.
    ///
    /// The returned chunk slice is backed by [`Self::Array`], so callers can
    /// construct [`Self::SimdT`] values without writing the lane-count const
    /// expression at the call site.
    #[must_use]
    fn simd_as_chunks(slice: &[Self]) -> (&[Self::Array], &[Self]);

    /// Splits a mutable slice into default SIMD-sized chunks and a scalar tail.
    ///
    /// This is the mutable counterpart of [`Self::simd_as_chunks`], intended
    /// for kernels that write whole SIMD chunks and then handle the remaining
    /// scalar lanes separately.
    #[must_use]
    fn simd_as_chunks_mut(slice: &mut [Self]) -> (&mut [Self::Array], &mut [Self]);
}

macro_rules! impl_simd_integer {
    ($($t:ty)*) => ($(
        impl SimdInteger for $t {
            const LANE_COUNT: usize = (VECTOR_BITS / <$t>::BITS) as usize;
            type Array = [$t; {Self::LANE_COUNT}];
            type Selector = [bool; {Self::LANE_COUNT}];
            type SimdT = Simd<$t, {Self::LANE_COUNT}>;
            type MaskT = Mask<<$t as SimdElement>::Mask, {Self::LANE_COUNT}>;
            type MaskReprT = Simd<<$t as SimdElement>::Mask, {Self::LANE_COUNT}>;

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

impl_simd_integer! {i8 i16 i32 i64 isize u8 u16 u32 u64 usize}

/// Unsigned integer types that can serve as SIMD lane elements.
pub trait SimdUnsignedInteger:
    UnsignedInteger + SimdInteger<SimdT: SimdUnsignedArray<Self>>
{
    /// Reinterprets the matching signed vector as unsigned lanes, preserving
    /// every lane's width, bit pattern and position. The companion vectors
    /// must have the same lane count. This does not encode an explicit modulus.
    #[must_use]
    fn simd_cast_from_signed(input: <Self::SignedInteger as SimdInteger>::SimdT) -> Self::SimdT
    where
        Self::SignedInteger: SimdInteger;
}

macro_rules! impl_simd_unsigned_integer {
    ($($t:ty)*) => ($(
        impl SimdUnsignedInteger for $t {
            #[inline]
            fn simd_cast_from_signed(
                input: <Self::SignedInteger as SimdInteger>::SimdT,
            ) -> Self::SimdT {
                core::simd::num::SimdInt::cast(input)
            }
        }
    )*)
}

impl_simd_unsigned_integer! {u8 u16 u32 u64 usize}

/// Unsigned SIMD vector extending [`SimdArray`] with carrying and widening
/// arithmetic required by higher-level crates.
pub trait SimdUnsignedArray<T>:
    SimdArray<T>
    + SimdUint<Scalar = T>
    + CarryingAdd<CarryT = T::MaskT>
    + BorrowingSub<BorrowT = T::MaskT>
    + WideningMul
    + CarryingMul
where
    T: UnsignedInteger + SimdInteger,
{
    /// Adds corresponding lanes, returning the wrapped sums and overflow mask.
    #[must_use]
    #[inline]
    fn overflowing_add(self, rhs: Self) -> (Self, T::MaskT) {
        let sum = self + rhs;
        let overflow = sum.simd_lt(self);
        (sum, overflow)
    }
}

impl<T, V> SimdUnsignedArray<T> for V
where
    T: UnsignedInteger + SimdInteger,
    V: SimdArray<T>
        + SimdUint<Scalar = T>
        + CarryingAdd<CarryT = T::MaskT>
        + BorrowingSub<BorrowT = T::MaskT>
        + WideningMul
        + CarryingMul,
{
}

/// Default-width SIMD vector extending [`Simd`] with the common operations
/// required by higher-level crates.
pub trait SimdArray<T: SimdInteger>
where
    Self: Send + Sync + Clone + Copy + Default,
    Self: PartialEq + PartialOrd + Eq + Ord,
    Self: Debug,
    Self: SimdPartialEq<Mask = T::MaskT> + SimdPartialOrd + SimdOrd,
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
    Self: Shl<Output = Self>,
    for<'a> Self: Add<&'a Self, Output = Self> + AddAssign<&'a Self>,
    for<'a> Self: Sub<&'a Self, Output = Self> + SubAssign<&'a Self>,
    for<'a> Self: Mul<&'a Self, Output = Self> + MulAssign<&'a Self>,
    for<'a> Self: Div<&'a Self, Output = Self> + DivAssign<&'a Self>,
    for<'a> Self: Rem<&'a Self, Output = Self> + RemAssign<&'a Self>,
    for<'a> Self: BitAnd<&'a Self, Output = Self> + BitAndAssign<&'a Self>,
    for<'a> Self: BitOr<&'a Self, Output = Self> + BitOrAssign<&'a Self>,
    for<'a> Self: BitXor<&'a Self, Output = Self> + BitXorAssign<&'a Self>,
{
    /// Constructs a new SIMD vector with all elements set to the given value.
    #[must_use]
    fn splat(value: T) -> Self;

    /// Converts an array to a SIMD vector.
    #[must_use]
    fn from_array(array: T::Array) -> Self;

    /// Converts a SIMD vector to an array.
    #[must_use]
    fn to_array(self) -> T::Array;

    /// Returns an array reference containing the entire SIMD vector.
    #[must_use]
    fn as_array(&self) -> &T::Array;

    /// Returns a mutable array reference containing the entire SIMD vector.
    #[must_use]
    fn as_mut_array(&mut self) -> &mut T::Array;
}

macro_rules! impl_simd_array {
    ($($t:ty)*) => ($(
        impl SimdArray<$t> for Simd<$t, {<$t>::LANE_COUNT}>  {
            #[inline]
            fn splat(value: $t) -> Self {
                Simd::<$t, {<$t>::LANE_COUNT}>::splat(value)
            }

            #[inline]
            fn from_array(array: <$t as SimdInteger>::Array) -> Self {
                Simd::<$t, {<$t>::LANE_COUNT}>::from_array(array)
            }

            #[inline]
            fn to_array(self) -> <$t as SimdInteger>::Array {
                self.to_array()
            }

            #[inline]
            fn as_array(&self) -> &<$t as SimdInteger>::Array {
                self.as_array()
            }

            #[inline]
            fn as_mut_array(&mut self) -> &mut <$t as SimdInteger>::Array {
                self.as_mut_array()
            }
        }
    )*)
}

impl_simd_array! {i8 i16 i32 i64 isize u8 u16 u32 u64 usize}

/// Mask for a default-width SIMD vector, providing bitwise and selection
/// operations.
#[allow(clippy::len_without_is_empty)]
pub trait SimdMaskArray<T: SimdInteger>
where
    Self: Send + Sync + Clone + Copy + Default,
    Self: PartialEq + PartialOrd,
    Self: Debug,
    Self: Select<T::SimdT>,
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
        T::LANE_COUNT
    }

    /// Choose elements from two vectors.
    ///
    /// For each element in the mask, choose the corresponding element from `true_values` if
    /// that element mask is true, and `false_values` if that element mask is false.
    #[must_use]
    fn select(self, true_values: T::SimdT, false_values: T::SimdT) -> T::SimdT;

    /// Constructs a mask by setting all elements to the given value.
    #[must_use]
    fn splat(value: bool) -> Self;

    /// Converts an array of bools to a SIMD mask.
    #[must_use]
    fn from_array(array: T::Selector) -> Self;

    /// Converts a SIMD mask to an array of bools.
    #[must_use]
    fn to_array(self) -> T::Selector;

    /// Converts a vector of integers to a mask, where 0 represents `false` and -1
    /// represents `true`.
    ///
    /// # Panics
    /// Panics if any element is not 0 or -1.
    #[must_use]
    #[track_caller]
    fn from_simd(value: T::MaskReprT) -> Self;

    /// Converts the mask to a vector of integers, where 0 represents `false`
    /// and -1 represents `true`.
    #[must_use]
    fn to_simd(self) -> T::MaskReprT;

    /// Returns true if any element is set, or false otherwise.
    #[must_use]
    fn any(self) -> bool;

    /// Returns true if all elements are set, or false otherwise.
    #[must_use]
    fn all(self) -> bool;
}

macro_rules! impl_mask_array {
    ($t:ty) => {
        impl SimdMaskArray<$t> for Mask<<$t as SimdElement>::Mask, { <$t>::LANE_COUNT }> {
            #[inline]
            fn select(
                self,
                true_values: <$t as SimdInteger>::SimdT,
                false_values: <$t as SimdInteger>::SimdT,
            ) -> <$t as SimdInteger>::SimdT {
                Select::select(self, true_values, false_values)
            }

            #[inline]
            fn splat(value: bool) -> Self {
                Self::splat(value)
            }

            #[inline]
            fn from_array(array: <$t as SimdInteger>::Selector) -> Self {
                Self::from_array(array)
            }

            #[inline]
            fn to_array(self) -> <$t as SimdInteger>::Selector {
                self.to_array()
            }

            #[inline]
            fn from_simd(value: <$t as SimdInteger>::MaskReprT) -> Self {
                Self::from_simd(value)
            }

            #[inline]
            fn to_simd(self) -> <$t as SimdInteger>::MaskReprT {
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

impl_mask_array! {i8}
impl_mask_array! {i16}
impl_mask_array! {i32}
impl_mask_array! {i64}
impl_mask_array! {isize}
impl_mask_array! {u8}
impl_mask_array! {u16}
impl_mask_array! {u32}
impl_mask_array! {u64}
impl_mask_array! {usize}

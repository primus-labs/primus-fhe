use core::fmt::Debug;

use primus_gcd::Xgcd;

use crate::{
    BorrowingSub, CarryingAdd, CarryingMul, DivRem, DivRemScalar, DivWide, FheInt, Integer,
    WideningMul,
};

/// An abstraction over unsigned integer types.
///
/// `UnsignedInteger` extends [`Integer`] with operations that only make sense
/// for unsigned values: carrying add/sub, widening/carrying multiplication,
/// division with remainder, fast wide division, the extended GCD
/// ([`Xgcd`]), and conversions from signed integers.
///
/// It is implemented for all standard Rust unsigned integer types (`u8`–`u128`,
/// `usize`) and serves as the principal value-type bound throughout the
/// crate hierarchy.
///
/// # Associated type
///
/// [`SignedInteger`](UnsignedInteger::SignedInteger) is the matching signed
/// type (e.g. `i64` for `u64`) and is used internally by algorithms such as
/// [`Xgcd::xgcd`] that need signed intermediate
/// cofactors.
pub trait UnsignedInteger:
    Integer
    + num_traits::Unsigned
    + CarryingAdd<CarryT = bool>
    + BorrowingSub<BorrowT = bool>
    + WideningMul
    + CarryingMul
    + DivRem
    + DivWide
    + DivRemScalar
    + Xgcd
    + TryFrom<usize, Error: Debug>
    + TryInto<usize, Error: Debug>
{
    /// The matching signed type (e.g. `i64` for `u64`).
    type SignedInteger: Integer;

    /// Returns `true` if and only if `self == 2^k` for some `k`.
    #[must_use]
    #[inline(always)]
    fn is_power_of_two(self) -> bool {
        self.count_ones() == 1
    }

    /// Reinterprets the signed companion value as `Self` using `as`.
    ///
    /// Performs a width-preserving bit-pattern cast (`value as Self`), so
    /// negative values become their two's-complement unsigned encoding (for
    /// example `-1i64` maps to `u64::MAX`). This is the inverse of
    /// [`wrapping_add_signed`](Self::wrapping_add_signed) when interpreting
    /// the result modulo `2^BITS`.
    fn cast_from_signed(value: Self::SignedInteger) -> Self;

    /// Wrapping (modular) addition with a signed integer. Computes `self + rhs`, wrapping around at the boundary of the type.
    fn wrapping_add_signed(self, rhs: Self::SignedInteger) -> Self;
}

macro_rules! impl_unsigned_integer {
    ($t:ty, $i:ty) => {
        impl UnsignedInteger for $t {
            type SignedInteger = $i;

            #[inline]
            fn cast_from_signed(value: Self::SignedInteger) -> Self {
                value as $t
            }

            #[inline(always)]
            fn wrapping_add_signed(self, rhs: Self::SignedInteger) -> Self {
                <$t>::wrapping_add_signed(self, rhs)
            }
        }
    };
}

impl_unsigned_integer! {u8, i8}
impl_unsigned_integer! {u16, i16}
impl_unsigned_integer! {u32, i32}
impl_unsigned_integer! {u64, i64}
impl_unsigned_integer! {u128, i128}
impl_unsigned_integer! {usize, isize}

#[cfg(not(feature = "simd"))]
/// Unsigned integer types used as the scalar basis of ciphertext arithmetic.
///
/// Only `u16`, `u32`, and `u64` are included — `u8` is too narrow, `u128`
/// lacks native SIMD support, and `usize` is platform-dependent.
pub trait FheUint: UnsignedInteger + FheInt {
    /// The matching signed type (e.g. `i64` for `u64`).
    type FheSignedInt: FheInt;

    /// Reinterprets the signed companion value as `Self` using `as`.
    ///
    /// Performs a width-preserving bit-pattern cast (`value as Self`), so
    /// negative values become their two's-complement unsigned encoding (for
    /// example `-1i64` maps to `u64::MAX`). This is the inverse of
    /// [`wrapping_add_signed`](Self::wrapping_add_signed) when interpreting
    /// the result modulo `2^BITS`.
    fn cast_from_signed(value: Self::FheSignedInt) -> Self;

    /// Wrapping (modular) addition with a signed integer. Computes `self + rhs`, wrapping around at the boundary of the type.
    fn wrapping_add_signed(self, rhs: Self::FheSignedInt) -> Self;
}

#[cfg(feature = "simd")]
/// Unsigned integer types used as the scalar basis of ciphertext arithmetic.
///
/// Only `u16`, `u32`, and `u64` are included — `u8` is too narrow, `u128`
/// lacks native SIMD support, and `usize` is platform-dependent.
pub trait FheUint: UnsignedInteger + FheInt + crate::SimdUnsignedInteger {
    /// The matching signed type (e.g. `i64` for `u64`).
    type FheSignedInt: FheInt;

    /// Reinterprets the signed companion value as `Self` using `as`.
    ///
    /// Performs a width-preserving bit-pattern cast (`value as Self`), so
    /// negative values become their two's-complement unsigned encoding (for
    /// example `-1i64` maps to `u64::MAX`). This is the inverse of
    /// [`wrapping_add_signed`](Self::wrapping_add_signed) when interpreting
    /// the result modulo `2^BITS`.
    fn cast_from_signed(value: Self::FheSignedInt) -> Self;

    /// Wrapping (modular) addition with a signed integer. Computes `self + rhs`, wrapping around at the boundary of the type.
    fn wrapping_add_signed(self, rhs: Self::FheSignedInt) -> Self;
}

macro_rules! impl_fhe_uint {
    ($t:ty, $i:ty) => {
        impl FheUint for $t {
            type FheSignedInt = $i;

            #[inline]
            fn cast_from_signed(value: Self::FheSignedInt) -> Self {
                value as $t
            }

            #[inline(always)]
            fn wrapping_add_signed(self, rhs: Self::FheSignedInt) -> Self {
                <$t>::wrapping_add_signed(self, rhs)
            }
        }
    };
}

impl_fhe_uint!(u16, i16);
impl_fhe_uint!(u32, i32);
impl_fhe_uint!(u64, i64);

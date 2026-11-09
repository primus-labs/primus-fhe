use super::{Integer, UnsignedInteger};

/// An abstraction over signed integer types.
///
/// `SignedInteger` extends [`Integer`] with sign-aware operations and a
/// width-matched unsigned companion. The companion relationship allows
/// generic code to distinguish a value's two's-complement representation
/// from its non-negative magnitude.
///
/// It is implemented for all standard Rust signed integer types (`i8`–`i128`,
/// `isize`).
pub trait SignedInteger: Integer + num_traits::Signed {
    /// The matching unsigned type with the same bit width.
    type UnsignedInteger: UnsignedInteger<SignedInteger = Self>;

    /// Reinterprets the unsigned companion value as `Self` using `as`.
    ///
    /// Values with the high bit set become negative, preserving the underlying
    /// two's-complement bit pattern.
    #[must_use]
    fn cast_from_unsigned(value: Self::UnsignedInteger) -> Self;

    /// Reinterprets this signed value as its unsigned companion using `as`.
    ///
    /// Negative values become their two's-complement unsigned encoding; for
    /// example, `-1i64` maps to `u64::MAX`.
    #[must_use]
    fn cast_to_unsigned(self) -> Self::UnsignedInteger;

    /// Returns the absolute value as the unsigned companion type.
    ///
    /// Unlike [`num_traits::Signed::abs`], this represents `Self::MIN`
    /// without overflow.
    #[must_use]
    fn unsigned_abs(self) -> Self::UnsignedInteger;
}

macro_rules! impl_signed_integer {
    ($signed:ty, $unsigned:ty) => {
        impl SignedInteger for $signed {
            type UnsignedInteger = $unsigned;

            #[inline]
            fn cast_from_unsigned(value: Self::UnsignedInteger) -> Self {
                value as $signed
            }

            #[inline]
            fn cast_to_unsigned(self) -> Self::UnsignedInteger {
                self as $unsigned
            }

            #[inline]
            fn unsigned_abs(self) -> Self::UnsignedInteger {
                <$signed>::unsigned_abs(self)
            }
        }
    };
}

impl_signed_integer!(i8, u8);
impl_signed_integer!(i16, u16);
impl_signed_integer!(i32, u32);
impl_signed_integer!(i64, u64);
impl_signed_integer!(i128, u128);
impl_signed_integer!(isize, usize);

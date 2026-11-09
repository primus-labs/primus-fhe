/// Fixed-width bit operations used by generic integer algorithms.
///
/// Primitive integers provide these operations as inherent methods. This trait
/// exposes their common behavior through [`Integer`](crate::Integer) bounds so
/// generic code can use it without naming a concrete primitive type.
///
/// Operations inspect the complete fixed-width representation. Signed values
/// use their two's-complement representation, and the width of `usize` and
/// `isize` depends on the target platform.
pub trait Bits {
    /// The number of bits in the fixed-width representation of this type.
    const BITS: u32;

    /// Returns the number of ones in the binary representation of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0b01001100u8;
    /// assert_eq!(<u8 as Bits>::count_ones(n), 3);
    /// ```
    #[doc(alias = "popcount")]
    #[doc(alias = "popcnt")]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn count_ones(self) -> u32;

    /// Returns the number of zeros in the binary representation of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0b01001100u8;
    /// assert_eq!(<u8 as Bits>::count_zeros(n), 5);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn count_zeros(self) -> u32;

    /// Returns the number of leading zeros in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0b0101000u16;
    /// assert_eq!(<u16 as Bits>::leading_zeros(n), 10);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn leading_zeros(self) -> u32;

    /// Returns the number of leading ones in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0xF00Du16;
    /// assert_eq!(<u16 as Bits>::leading_ones(n), 4);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn leading_ones(self) -> u32;

    /// Returns the number of trailing zeros in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0b0101000u16;
    /// assert_eq!(<u16 as Bits>::trailing_zeros(n), 3);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn trailing_zeros(self) -> u32;

    /// Returns the number of trailing ones in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::Bits;
    ///
    /// let n = 0xBEEFu16;
    /// assert_eq!(<u16 as Bits>::trailing_ones(n), 4);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn trailing_ones(self) -> u32;

    /// Reverses the order of bits in the fixed-width representation of
    /// `self`.
    ///
    /// The least-significant bit becomes the most-significant bit, the second
    /// least-significant bit becomes the second most-significant bit, and so
    /// on.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn reverse_bits(self) -> Self;
}

macro_rules! impl_bits {
    ($($T:ty),*) => {
        $(
            impl Bits for $T {
                const BITS: u32 = <$T>::BITS;

                #[inline]
                fn count_ones(self) -> u32 {
                    <$T>::count_ones(self)
                }

                #[inline]
                fn count_zeros(self) -> u32 {
                    <$T>::count_zeros(self)
                }

                #[inline]
                fn leading_zeros(self) -> u32 {
                    <$T>::leading_zeros(self)
                }

                #[inline]
                fn leading_ones(self) -> u32 {
                    <$T>::leading_ones(self)
                }

                #[inline]
                fn trailing_zeros(self) -> u32 {
                    <$T>::trailing_zeros(self)
                }

                #[inline]
                fn trailing_ones(self) -> u32 {
                    <$T>::trailing_ones(self)
                }

                #[inline]
                fn reverse_bits(self) -> Self {
                    <$T>::reverse_bits(self)
                }
            }
        )*
    };
}

impl_bits! {i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize}

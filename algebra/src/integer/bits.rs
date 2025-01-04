/// Extension trait to provide access to bits of integers.
pub trait Bits {
    /// The number of bits this type has.
    const BITS: u32;

    /// Returns the number of ones in the binary representation of `self`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let n = 0b01001100u8;
    ///
    /// assert_eq!(n.count_ones(), 3);
    /// ```
    fn count_ones(self) -> u32;

    /// Returns the number of leading zeros in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let n = 0b0101000u16;
    ///
    /// assert_eq!(n.leading_zeros(), 10);
    /// ```
    fn leading_zeros(self) -> u32;

    /// Returns the number of trailing zeros in the binary representation
    /// of `self`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let n = 0b0101000u16;
    ///
    /// assert_eq!(n.trailing_zeros(), 3);
    /// ```
    fn trailing_zeros(self) -> u32;
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
                fn leading_zeros(self) -> u32 {
                    <$T>::leading_zeros(self)
                }

                #[inline]
                fn trailing_zeros(self) -> u32 {
                    <$T>::trailing_zeros(self)
                }
            }
        )*
    };
}

impl_bits!(i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize);

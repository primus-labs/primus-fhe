/// Extension trait to provide access to bits of integers.
pub trait Bits {
    /// The number of bits this type has.
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    fn trailing_ones(self) -> u32;
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
            }
        )*
    };
}

impl_bits! {i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bits_per_type<T>(n: T, v: &Vec<u32>)
    where
        T: Bits + Copy,
    {
        assert_eq!(<T as Bits>::count_ones(n), v[0]);
        assert_eq!(<T as Bits>::count_zeros(n), v[1]);
        assert_eq!(<T as Bits>::leading_zeros(n), v[2]);
        assert_eq!(<T as Bits>::leading_ones(n), v[3]);
        assert_eq!(<T as Bits>::trailing_zeros(n), v[4]);
        assert_eq!(<T as Bits>::trailing_ones(n), v[5]);
    }

    #[test]
    fn test_bits() {
        let n = 0b0100_1100u8;
        let mut v = vec![3, 5, 1, 0, 2, 0];

        let m = 0b1100_1010u8 as i8;
        let mut w = vec![4, 4, 0, 2, 1, 0];

        test_bits_per_type::<u8>(n, &v);
        test_bits_per_type::<i8>(m, &w);

        let n: u16 = n as u16;
        v[1] += 8;
        v[2] += 8;
        test_bits_per_type::<u16>(n, &v);

        let m: i16 = m as i16;
        w[0] += 8;
        w[3] += 8;
        test_bits_per_type::<i16>(m, &w);

        let n: u32 = n as u32;
        v[1] += 16;
        v[2] += 16;
        test_bits_per_type::<u32>(n, &v);

        let m: i32 = m as i32;
        w[0] += 16;
        w[3] += 16;
        test_bits_per_type::<i32>(m, &w);

        let n: usize = n as usize;
        #[cfg(target_pointer_width = "32")]
        test_bits_per_type::<usize>(n, &v);

        let m: isize = m as isize;
        #[cfg(target_pointer_width = "32")]
        test_bits_per_type::<isize>(m, &w);

        let n: u64 = n as u64;
        v[1] += 32;
        v[2] += 32;
        test_bits_per_type::<u64>(n, &v);

        let m: i64 = m as i64;
        w[0] += 32;
        w[3] += 32;
        test_bits_per_type::<i64>(m, &w);

        let n: usize = n as usize;
        #[cfg(target_pointer_width = "64")]
        test_bits_per_type::<usize>(n, &v);

        let m: isize = m as isize;
        #[cfg(target_pointer_width = "64")]
        test_bits_per_type::<isize>(m, &w);

        let n: u128 = n as u128;
        v[1] += 64;
        v[2] += 64;
        test_bits_per_type::<u128>(n, &v);

        let m: i128 = m as i128;
        w[0] += 64;
        w[3] += 64;
        test_bits_per_type::<i128>(m, &w);
    }
}

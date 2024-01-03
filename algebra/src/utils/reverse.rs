/// This trait mainly define a function that reverse
/// some least significant bits of the `Self`.
pub trait ReverseLsbs {
    /// Reverse some least significant bits of the `Self`,
    /// and set other bits to zero.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(0b00001101u8.reverse_lsbs(4), 0b00001011u8);
    /// assert_eq!(0b01101101u8.reverse_lsbs(4), 0b00001011u8);
    /// ```
    fn reverse_lsbs(self, bits: u32) -> Self;
}

macro_rules! impl_reverse_lsbs_for_unsigned {
    ($($T:ty),*) => {
        $(impl ReverseLsbs for $T {
            #[inline]
            fn reverse_lsbs(self, bits: u32) -> Self {
                debug_assert!(bits < Self::BITS);
                if self == 0 || bits == 0 {
                    0
                } else {
                    self.reverse_bits() >> (Self::BITS - bits)
                }
            }
        })*
    };
}

impl_reverse_lsbs_for_unsigned!(u8, u16, u32, u64, u128, usize);

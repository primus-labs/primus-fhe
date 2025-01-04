macro_rules! impl_powof2_modulus {
    (impl PowOf2Modulus<$ValueT:ty>) => {
        impl PowOf2Modulus<$ValueT> {
            /// Creates a [`PowOf2Modulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            #[inline]
            pub const fn new(value: $ValueT) -> Self {
                assert!(value > 1 && value.is_power_of_two());
                Self { mask: value - 1 }
            }

            /// Creates a [`PowOf2Modulus<T>`] instance.
            ///
            /// - `mask`: modulus value minus one.
            #[inline]
            pub const fn new_with_mask(mask: $ValueT) -> Self {
                assert!(mask.count_zeros() == mask.leading_zeros() && mask > 0);
                assert!(
                    mask.leading_zeros() > 0,
                    "NativeModulus<T> supports modulus value such as 2⁸, 2¹⁶, 2³², 2⁶⁴, 2¹²⁸"
                );
                Self { mask }
            }
        }
    };
}

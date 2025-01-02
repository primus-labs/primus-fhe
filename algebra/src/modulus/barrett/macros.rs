macro_rules! impl_barrett_modulus {
    (impl BarrettModulus<$ValueT:ty>; WideType: $WideT:ty) => {
        impl BarrettModulus<$ValueT> {
            /// Creates a [`BarrettModulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            ///
            /// # Panics
            ///
            /// The `value` must be greater than 1. It is crucial to reserve 2 bits of padding
            /// for future calculations to prevent overflow errors that could occur
            /// if the primitive data type does not have sufficient space to accommodate the computation.
            #[must_use]
            pub const fn new(value: $ValueT) -> Self {
                const HALF_BITS: u32 = <$ValueT>::BITS >> 1;
                const HALF: $ValueT = <$ValueT>::MAX >> HALF_BITS;

                #[inline]
                const fn div_rem(numerator: $ValueT, divisor: $ValueT) -> ($ValueT, $ValueT) {
                    (numerator / divisor, numerator % divisor)
                }

                #[inline]
                const fn div_wide(hi: $ValueT, divisor: $ValueT) -> ($ValueT, $ValueT) {
                    let lhs = (hi as $WideT) << <$ValueT>::BITS;
                    let rhs = divisor as $WideT;
                    ((lhs / rhs) as $ValueT, (lhs % rhs) as $ValueT)
                }

                #[inline]
                const fn div_half(rem: $ValueT, divisor: $ValueT) -> ($ValueT, $ValueT) {
                    let (hi, rem) = div_rem(rem << HALF_BITS, divisor);
                    let (lo, rem) = div_rem(rem << HALF_BITS, divisor);
                    ((hi << HALF_BITS) | lo, rem)
                }

                const fn div_inplace(value: $ValueT) -> ([$ValueT; 2], $ValueT) {
                    let mut numerator = [0, 0];
                    let rem;

                    if value <= HALF {
                        let (q, r) = div_half(1, value);
                        numerator[1] = q;

                        let (q, r) = div_half(r, value);
                        numerator[0] = q;
                        rem = r;
                    } else {
                        let (q, r) = div_wide(1, value);
                        numerator[1] = q;

                        let (q, r) = div_wide(r, value);
                        numerator[0] = q;
                        rem = r;
                    }
                    (numerator, rem)
                }

                match value {
                    0 | 1 => panic!("modulus can't be 0 or 1."),
                    _ => {
                        let bit_count = <$ValueT>::BITS - value.leading_zeros();
                        assert!(bit_count < <$ValueT>::BITS - 1);

                        let (numerator, _) = div_inplace(value);

                        Self {
                            value,
                            ratio: numerator,
                        }
                    }
                }
            }

            // /// Returns the bit count of this [`BarrettModulus<T>`].
            // #[inline]
            // pub const fn bit_count(&self) -> u32 {
            //     <$ValueT>::BITS - self.value.leading_zeros()
            // }
        }
    };
}

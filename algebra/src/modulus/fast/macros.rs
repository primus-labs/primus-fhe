macro_rules! impl_fast_modulus {
    (impl FastModulus<$ValueT:ty>; WideType: $WideT:ty) => {
        impl FastModulus<$ValueT> {
            /// Creates a [`FastModulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            #[must_use]
            pub const fn new(value: $ValueT) -> Self {
                match value {
                    0 | 1 => panic!("modulus can't be 0 or 1."),
                    _ => {
                        let ratio = <$WideT>::MAX / value as $WideT + 1;
                        let ratio = [ratio as $ValueT, (ratio >> <$ValueT>::BITS) as $ValueT];

                        Self { value, ratio }
                    }
                }
            }
        }
    };
}

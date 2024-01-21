macro_rules! impl_powof2_modulus {
    (impl PowOf2Modulus<$SelfT:ty>) => {
        impl PowOf2Modulus<$SelfT> {
            /// Creates a [`PowOf2Modulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            pub const fn new(value: $SelfT) -> Self {
                assert!(value > 1 && value.is_power_of_two());
                Self { mask: value - 1 }
            }
        }

        impl crate::reduce::Reduce<PowOf2Modulus<$SelfT>> for $SelfT {
            type Output = Self;

            #[inline]
            fn reduce(self, modulus: PowOf2Modulus<$SelfT>) -> Self::Output {
                self & modulus.mask()
            }
        }

        impl crate::reduce::ReduceAssign<PowOf2Modulus<$SelfT>> for $SelfT {
            #[inline]
            fn reduce_assign(&mut self, modulus: PowOf2Modulus<$SelfT>) {
                *self &= modulus.mask();
            }
        }
    };
}

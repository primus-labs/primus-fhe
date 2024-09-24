macro_rules! impl_powof2_modulus {
    (impl PowOf2Modulus<$SelfT:ty>) => {
        impl PowOf2Modulus<$SelfT> {
            /// Creates a [`PowOf2Modulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            #[inline]
            pub const fn new(value: $SelfT) -> Self {
                assert!(value > 1 && value.is_power_of_two());
                Self { mask: value - 1 }
            }
        }

        impl $crate::reduce::Reduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn reduce(self, modulus: PowOf2Modulus<Self>) -> Self::Output {
                self & modulus.mask()
            }
        }

        impl $crate::reduce::ReduceAssign<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn reduce_assign(&mut self, modulus: PowOf2Modulus<Self>) {
                *self &= modulus.mask();
            }
        }

        impl $crate::reduce::AddReduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn add_reduce(self, rhs: Self, modulus: PowOf2Modulus<Self>) -> Self::Output {
                self.wrapping_add(rhs) & modulus.mask()
            }
        }

        impl $crate::reduce::AddReduceAssign<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn add_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<Self>) {
                *self = self.wrapping_add(rhs) & modulus.mask();
            }
        }

        impl $crate::reduce::SubReduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn sub_reduce(self, rhs: Self, modulus: PowOf2Modulus<Self>) -> Self::Output {
                self.wrapping_sub(rhs) & modulus.mask()
            }
        }

        impl $crate::reduce::SubReduceAssign<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn sub_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<Self>) {
                *self = self.wrapping_sub(rhs) & modulus.mask();
            }
        }

        impl $crate::reduce::NegReduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn neg_reduce(self, modulus: PowOf2Modulus<Self>) -> Self::Output {
                self.wrapping_neg() & modulus.mask()
            }
        }

        impl $crate::reduce::NegReduceAssign<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn neg_reduce_assign(&mut self, modulus: PowOf2Modulus<Self>) {
                *self = self.wrapping_neg() & modulus.mask();
            }
        }

        impl $crate::reduce::MulReduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn mul_reduce(self, rhs: Self, modulus: PowOf2Modulus<Self>) -> Self::Output {
                self.wrapping_mul(rhs) & modulus.mask()
            }
        }

        impl $crate::reduce::MulReduceAssign<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn mul_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<Self>) {
                *self = self.wrapping_mul(rhs) & modulus.mask();
            }
        }

        impl<E> $crate::reduce::ExpReduce<PowOf2Modulus<Self>, E> for $SelfT
        where
            E: ::num_traits::PrimInt + ::std::ops::ShrAssign<u32> + $crate::Bits,
        {
            fn exp_reduce(self, mut exp: E, modulus: PowOf2Modulus<Self>) -> Self {
                use $crate::reduce::MulReduce;
                if exp.is_zero() {
                    return 1;
                }

                debug_assert!(self <= modulus.mask());

                let mut power: Self = self;

                let exp_trailing_zeros = exp.trailing_zeros();
                if exp_trailing_zeros > 0 {
                    for _ in 0..exp_trailing_zeros {
                        power = power.mul_reduce(power, modulus);
                    }
                    exp >>= exp_trailing_zeros;
                }

                if exp.is_one() {
                    return power;
                }

                let mut intermediate: Self = power;
                for _ in 1..(<E as $crate::Bits>::BITS - exp.leading_zeros()) {
                    exp >>= 1;
                    power = power.mul_reduce(power, modulus);
                    if !(exp & E::one()).is_zero() {
                        intermediate = intermediate.mul_reduce(power, modulus);
                    }
                }
                intermediate
            }
        }

        impl $crate::reduce::ExpPowOf2Reduce<PowOf2Modulus<Self>> for $SelfT {
            #[inline]
            fn exp_power_of_2_reduce(self, exp_log: u32, modulus: PowOf2Modulus<Self>) -> Self {
                use $crate::reduce::MulReduce;
                let mut power: Self = self;

                for _ in 0..exp_log {
                    power = power.mul_reduce(power, modulus);
                }

                power
            }
        }

        impl $crate::reduce::DotProductReduce<PowOf2Modulus<Self>> for $SelfT {
            type Output = Self;

            #[inline]
            fn dot_product_reduce(
                a: impl AsRef<[Self]>,
                b: impl AsRef<[Self]>,
                modulus: PowOf2Modulus<Self>,
            ) -> Self::Output {
                use $crate::reduce::Reduce;
                let a = a.as_ref();
                let b = b.as_ref();
                debug_assert_eq!(a.len(), b.len());
                a.iter()
                    .zip(b)
                    .fold(0, |acc: $SelfT, (&x, &y)| {
                        x.wrapping_mul(y).wrapping_add(acc)
                    })
                    .reduce(modulus)
            }
        }
    };
}

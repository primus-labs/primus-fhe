macro_rules! impl_reduce_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl $crate::reduce::AddReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn add_reduce(self, rhs: Self, modulus: Self) -> Self::Output {
                let r = self + rhs;
                if r >= modulus {
                    r - modulus
                } else {
                    r
                }
            }
        }

        impl $crate::reduce::AddReduceAssign<Self> for $t {
            #[inline]
            fn add_reduce_assign(&mut self, rhs: Self, modulus: Self) {
                let r = *self + rhs;
                *self = if r >= modulus {
                    r - modulus
                } else {
                    r
                };
            }
        }

        impl $crate::reduce::SubReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn sub_reduce(self, rhs: Self, modulus: Self) -> Self::Output {
                if self >= rhs {
                    self - rhs
                } else {
                    modulus - rhs + self
                }
            }
        }

        impl $crate::reduce::SubReduceAssign<Self> for $t {
            #[inline]
            fn sub_reduce_assign(&mut self, rhs: Self, modulus: Self) {
                if *self >= rhs {
                    *self -= rhs;
                } else {
                    *self += modulus - rhs;
                }
            }
        }

        impl $crate::reduce::NegReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn neg_reduce(self, modulus: Self) -> Self::Output {
                if self == 0 {
                    0
                } else {
                    modulus - self
                }
            }
        }

        impl $crate::reduce::NegReduceAssign<Self> for $t {
            #[inline]
            fn neg_reduce_assign(&mut self, modulus: Self) {
                if *self != 0 {
                    *self = modulus - *self;
                }
            }
        }

        impl $crate::reduce::InvReduce for $t {
            fn inv_reduce(self, modulus: Self) -> Self {
                debug_assert!(self < modulus);
                use $crate::utils::ExtendedGCD;

                let (_, inv, gcd) = ExtendedGCD::extended_gcd(modulus, self);

                assert_eq!(gcd, 1);

                if inv > 0 {
                    inv as Self
                } else {
                    (inv + modulus as <Self as ExtendedGCD>::SignedT) as Self
                }
            }
        }

        impl $crate::reduce::TryInvReduce for $t {
            fn try_inv_reduce(self, modulus: Self) -> Result<Self, crate::AlgebraError> {
                debug_assert!(self < modulus);
                use $crate::utils::ExtendedGCD;

                let (_, inv, gcd) = ExtendedGCD::extended_gcd(modulus, self);

                if gcd == 1 {
                    if inv > 0 {
                        Ok(inv as Self)
                    } else {
                        Ok((inv + modulus as <Self as ExtendedGCD>::SignedT) as Self)
                    }
                } else {
                    Err($crate::AlgebraError::NoReduceInverse {
                        value: self.to_string(),
                        modulus: modulus.to_string(),
                    })
                }
            }
        }
    )*};
}

impl_reduce_ops_for_primitive!(u8, u16, u32, u64);

macro_rules! impl_non_reduce_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl $crate::reduce::Reduce<()> for $t {
            type Output = Self;

            #[inline]
            fn reduce(self, _modulus: ()) -> Self::Output {
                self
            }
        }

        impl $crate::reduce::ReduceAssign<()> for $t {
            #[inline]
            fn reduce_assign(&mut self, _modulus: ()) {}
        }

        impl $crate::reduce::AddReduce<()> for $t {
            type Output = Self;

            #[inline]
            fn add_reduce(self, rhs: Self, _modulus: ()) -> Self::Output {
                self.wrapping_add(rhs)
            }
        }

        impl $crate::reduce::AddReduceAssign<()> for $t {
            #[inline]
            fn add_reduce_assign(&mut self, rhs: Self, _modulus: ()) {
                *self = self.wrapping_add(rhs)
            }
        }

        impl $crate::reduce::SubReduce<()> for $t {
            type Output = Self;

            #[inline]
            fn sub_reduce(self, rhs: Self, _modulus: ()) -> Self::Output {
                self.wrapping_sub(rhs)
            }
        }

        impl $crate::reduce::SubReduceAssign<()> for $t {
            #[inline]
            fn sub_reduce_assign(&mut self, rhs: Self, _modulus: ()) {
                *self = self.wrapping_sub(rhs);
            }
        }

        impl $crate::reduce::NegReduce<()> for $t {
            type Output = Self;

            #[inline]
            fn neg_reduce(self, _modulus: ()) -> Self::Output {
                self.wrapping_neg()
            }
        }

        impl $crate::reduce::NegReduceAssign<()> for $t {
            #[inline]
            fn neg_reduce_assign(&mut self, _modulus: ()) {
                *self = self.wrapping_neg();
            }
        }

        impl $crate::reduce::MulReduce<()> for $t {
            type Output = Self;

            #[inline]
            fn mul_reduce(self, rhs: Self, _modulus: ()) -> Self::Output {
                self.wrapping_mul(rhs)
            }
        }

        impl $crate::reduce::MulReduceAssign<()> for $t {
            #[inline]
            fn mul_reduce_assign(&mut self, rhs: Self, _modulus: ()) {
                *self = self.wrapping_mul(rhs)
            }
        }

        impl $crate::reduce::DivReduce<()> for $t {
            type Output = Self;

            #[inline]
            fn div_reduce(self, rhs: Self, _modulus: ()) -> Self::Output {
                self.wrapping_div(rhs)
            }
        }

        impl $crate::reduce::DivReduceAssign<()> for $t {
            #[inline]
            fn div_reduce_assign(&mut self, rhs: Self, _modulus: ()) {
                *self = self.wrapping_div(rhs)
            }
        }

        impl $crate::reduce::ExpReduce<(), u32> for $t {
            #[inline]
            fn exp_reduce(self, exp: u32, _modulus: ()) -> Self {
                self.wrapping_pow(exp)
            }
        }
    )*};
}

impl_non_reduce_ops_for_primitive! {u8, u16, u32, u64}

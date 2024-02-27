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
                modulus - self
            }
        }

        impl $crate::reduce::NegReduceAssign<Self> for $t {
            #[inline]
            fn neg_reduce_assign(&mut self, modulus: Self) {
                *self = modulus - *self;
            }
        }

        impl $crate::reduce::InvReduce for $t {
            fn inv_reduce(self, modulus: Self) -> Self {
                debug_assert!(self < modulus);
                use $crate::utils::ExtendedGCD;

                let (_, inv, gcd) = ExtendedGCD::extended_gcd(modulus, self);

                debug_assert_eq!(gcd, 1);

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

macro_rules! impl_lazy_reduce_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl $crate::reduce::LazyAddReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn lazy_add_reduce(self, rhs: Self, modulus: Self) -> Self::Output {
                let twice_modulus = modulus<<1;
                let r = self + rhs;
                if r >= twice_modulus {
                    r - twice_modulus
                } else {
                    r
                }
            }
        }

        impl $crate::reduce::LazyAddReduceAssign<Self> for $t {
            #[inline]
            fn lazy_add_reduce_assign(&mut self, rhs: Self, modulus: Self) {
                let twice_modulus = modulus<<1;
                let r = *self + rhs;
                *self = if r >= twice_modulus {
                    r - twice_modulus
                } else {
                    r
                };
            }
        }

        impl $crate::reduce::LazySubReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn lazy_sub_reduce(self, rhs: Self, modulus: Self) -> Self::Output {
                if self >= rhs {
                    self - rhs
                } else {
                    (modulus << 1) - rhs + self
                }
            }
        }

        impl $crate::reduce::LazySubReduceAssign<Self> for $t {
            #[inline]
            fn lazy_sub_reduce_assign(&mut self, rhs: Self, modulus: Self) {
                if *self >= rhs {
                    *self -= rhs;
                } else {
                    *self += (modulus << 1) - rhs;
                }
            }
        }

        impl $crate::reduce::LazyNegReduce<Self> for $t {
            type Output = Self;

            #[inline]
            fn lazy_neg_reduce(self, modulus: Self) -> Self::Output {
                (modulus << 1) - self
            }
        }

        impl $crate::reduce::LazyNegReduceAssign<Self> for $t {
            #[inline]
            fn lazy_neg_reduce_assign(&mut self, modulus: Self) {
                *self = (modulus << 1) - *self;
            }
        }
    )*};
}

impl_lazy_reduce_ops_for_primitive!(u8, u16, u32, u64);

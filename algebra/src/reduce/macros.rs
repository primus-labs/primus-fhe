macro_rules! impl_reduce_ops_for_primitive {
    ($($ValueT:ty),*) => {$(
        impl $crate::reduce::Modulus<$ValueT> for $ValueT {
            fn from_value(value: $crate::reduce::ModulusValue<$ValueT>) -> Self {
                match value {
                    $crate::reduce::ModulusValue::Native => panic!("Not match for native"),
                    $crate::reduce::ModulusValue::PowerOf2(value)
                    | $crate::reduce::ModulusValue::Prime(value)
                    | $crate::reduce::ModulusValue::Others(value) => value,
                }
            }

            #[inline(always)]
            fn modulus_value(&self) -> $crate::reduce::ModulusValue<$ValueT> {
                $crate::reduce::ModulusValue::Others(*self)
            }

            #[inline(always)]
            fn modulus_minus_one(&self) -> $ValueT {
                *self - 1
            }
        }

        impl $crate::reduce::ReduceOnce<Self> for $ValueT {
            type Output = $ValueT;

            #[inline]
            fn reduce_once(self, value: Self) -> Self::Output {
                if value >= self {
                    value - self
                } else {
                    value
                }
            }
        }

        impl $crate::reduce::ReduceOnceAssign<Self> for $ValueT {
            #[inline]
            fn reduce_once_assign(self, value: &mut Self) {
                if *value >= self {
                    *value -= self;
                };
            }
        }

        impl $crate::reduce::ReduceAdd<Self> for $ValueT {
            type Output = $ValueT;

            #[inline]
            fn reduce_add(self, a: Self, b: Self) -> Self {
                if self - b > a{
                    a + b
                } else {
                    a.wrapping_add(b).wrapping_sub(self)
                }
            }
        }

        impl $crate::reduce::ReduceAddAssign<Self> for $ValueT {
            #[inline]
            fn reduce_add_assign(self, a: &mut Self, b: Self) {
                if self - b > *a{
                    *a += b;
                } else {
                    *a = a.wrapping_add(b).wrapping_sub(self)
                }
            }
        }

        impl $crate::reduce::ReduceDouble<Self> for $ValueT {
            type Output = $ValueT;

            #[inline]
            fn reduce_double(self, value: Self) -> Self {
                use $crate::reduce::ReduceAdd;
                self.reduce_add(value, value)
            }
        }

        impl $crate::reduce::ReduceDoubleAssign<Self> for $ValueT {
            #[inline]
            fn reduce_double_assign(self, value: &mut Self) {
                use $crate::reduce::ReduceAdd;
                *value = self.reduce_add(*value, *value);
            }
        }

        impl $crate::reduce::ReduceSub<Self> for $ValueT {
            type Output = $ValueT;

            #[inline]
            fn reduce_sub(self, a: Self, b: Self) -> Self {
                if b > a {
                    a.wrapping_sub(b).wrapping_add(self)
                } else {
                    a - b
                }
            }
        }

        impl $crate::reduce::ReduceSubAssign<Self> for $ValueT {
            #[inline]
            fn reduce_sub_assign(self, a: &mut Self, b: Self) {
                if b > *a {
                    *a = a.wrapping_sub(b).wrapping_add(self);
                } else {
                    *a -= b;
                }
            }
        }

        impl $crate::reduce::ReduceNeg<Self> for $ValueT {
            type Output = $ValueT;

            #[inline]
            fn reduce_neg(self, value: Self) -> Self {
                if value == 0 {
                    0
                } else {
                    self - value
                }
            }
        }

        impl $crate::reduce::ReduceNegAssign<Self> for $ValueT {
            #[inline]
            fn reduce_neg_assign(self, value: &mut Self) {
                if *value != 0 {
                    *value = self - *value;
                }
            }
        }

        impl $crate::reduce::ReduceInv<Self> for $ValueT {
            type Output = Self;

            #[inline]
            fn reduce_inv(self, value: $ValueT) -> Self::Output {
                debug_assert!(self > value);

                let (inv, gcd) = $crate::arith::Xgcd::gcdinv(value, self);
                assert_eq!(gcd, 1, "No {value}^(-1) mod {}", self);

                inv
            }
        }

        impl $crate::reduce::ReduceInvAssign<Self> for $ValueT {
            #[inline]
            fn reduce_inv_assign(self, value: &mut $ValueT) {
                debug_assert!(self > *value);

                let (inv, gcd) = $crate::arith::Xgcd::gcdinv(*value, self);
                assert_eq!(gcd, 1, "No {}^(-1) mod {}", *value, self);

                *value = inv;
            }
        }

        impl $crate::reduce::TryReduceInv<Self> for $ValueT {
            type Output = Self;

            fn try_reduce_inv(self, value: Self) -> Result<Self::Output, crate::AlgebraError> {
                debug_assert!(self > value);

                let (inv, gcd) = $crate::arith::Xgcd::gcdinv(value, self);

                if gcd == 1 {
                    Ok(inv)
                } else {
                    Err($crate::AlgebraError::NoInverse {
                        value: Box::new(value),
                        modulus: Box::new(self),
                    })
                }
            }
        }
    )*};
}

impl_reduce_ops_for_primitive!(u8, u16, u32, u64, u128, usize);

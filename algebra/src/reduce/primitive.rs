use crate::reduce::{
    AddReduce, AddReduceAssign, InvReduce, NegReduce, NegReduceAssign, SubReduce, SubReduceAssign,
};
use crate::utils::ExtendedGCD;

use super::TryInvReduce;

macro_rules! impl_modulo_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl AddReduce<$t> for $t {
            type Output = $t;

            #[inline]
            fn add_reduce(self, rhs: Self, modulus: $t) -> Self::Output {
                let r = self + rhs;
                if r >= modulus {
                    r - modulus
                } else {
                    r
                }
            }
        }

        impl AddReduceAssign<$t> for $t {
            #[inline]
            fn add_reduce_assign(&mut self, rhs: Self, modulus: $t) {
                let r = *self + rhs;
                *self = if r >= modulus {
                    r - modulus
                } else {
                    r
                };
            }
        }

        impl SubReduce<$t> for $t {
            type Output = $t;

            #[inline]
            fn sub_reduce(self, rhs: Self, modulus: $t) -> Self::Output {
                if self >= rhs {
                    self - rhs
                } else {
                    modulus - rhs + self
                }
            }
        }

        impl SubReduceAssign<$t> for $t {
            #[inline]
            fn sub_reduce_assign(&mut self, rhs: Self, modulus: $t) {
                if *self >= rhs {
                    *self -= rhs;
                } else {
                    *self += modulus - rhs;
                }
            }
        }

        impl NegReduce<$t> for $t {
            type Output = $t;

            #[inline]
            fn neg_reduce(self, modulus: $t) -> Self::Output {
                modulus - self
            }
        }

        impl NegReduceAssign<$t> for $t {
            #[inline]
            fn neg_reduce_assign(&mut self, modulus: $t) {
                *self = modulus - *self;
            }
        }

        impl InvReduce for $t {
            fn inv_reduce(self, modulus: Self) -> Self {
                debug_assert!(self < modulus);

                let (_, inv, gcd) = Self::extended_gcd(modulus, self);

                debug_assert_eq!(gcd, 1);

                if inv > 0 {
                    inv as $t
                } else {
                    (inv + modulus as <$t as ExtendedGCD>::SignedT) as $t
                }
            }
        }

        impl TryInvReduce for $t {
            fn try_inv_reduce(self, modulus: Self) -> Result<Self, crate::AlgebraError> {
                debug_assert!(self < modulus);

                let (_, inv, gcd) = Self::extended_gcd(modulus, self);

                if gcd == 1 {
                    if inv > 0 {
                        Ok(inv as Self)
                    } else {
                        Ok((inv + modulus as <Self as ExtendedGCD>::SignedT) as Self)
                    }
                } else {
                    Err(crate::AlgebraError::NoReduceInverse {
                        value: self.to_string(),
                        modulus: modulus.to_string(),
                    })
                }
            }
        }
    )*};
}

impl_modulo_ops_for_primitive!(u8, u16, u32, u64);

use crate::modulo_traits::{
    AddModulo, AddModuloAssign, InvModulo, NegModulo, NegModuloAssign, SubModulo, SubModuloAssign,
};
use crate::utils::ExtendedGCD;

use super::TryInvModulo;

macro_rules! impl_modulo_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl AddModulo<$t> for $t {
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

        impl AddModuloAssign<$t> for $t {
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

        impl SubModulo<$t> for $t {
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

        impl SubModuloAssign<$t> for $t {
            #[inline]
            fn sub_reduce_assign(&mut self, rhs: Self, modulus: $t) {
                if *self >= rhs {
                    *self -= rhs;
                } else {
                    *self += modulus - rhs;
                }
            }
        }

        impl NegModulo<$t> for $t {
            type Output = $t;

            #[inline]
            fn neg_reduce(self, modulus: $t) -> Self::Output {
                if self == 0 {
                    0
                } else {
                    modulus - self
                }
            }
        }

        impl NegModuloAssign<$t> for $t {
            #[inline]
            fn neg_reduce_assign(&mut self, modulus: $t) {
                *self = modulus - *self;
            }
        }

        impl InvModulo for $t {
            fn inv_reduce(self, modulus: Self) -> Self {
                assert!(self < modulus);

                let (_, inv, gcd) = Self::extended_gcd(modulus, self);

                assert_eq!(gcd, 1);

                if inv > 0 {
                    inv as $t
                } else {
                    (inv + modulus as <$t as ExtendedGCD>::SignedT) as $t
                }
            }
        }

        impl TryInvModulo for $t {
            fn try_inv_reduce(self, modulus: Self) -> Result<Self, crate::AlgebraError> {
                assert!(self < modulus);

                let (_, inv, gcd) = Self::extended_gcd(modulus, self);

                if gcd == 1 {
                    if inv > 0 {
                        Ok(inv as Self)
                    } else {
                        Ok((inv + modulus as <Self as ExtendedGCD>::SignedT) as Self)
                    }
                } else {
                    Err(crate::AlgebraError::NoModuloInverse {
                        value: self.to_string(),
                        modulus: modulus.to_string(),
                    })
                }
            }
        }
    )*};
}

impl_modulo_ops_for_primitive!(u8, u16, u32, u64);

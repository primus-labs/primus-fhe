use crate::modulo::{
    AddModulo, AddModuloAssign, InvModulo, NegModulo, NegModuloAssign, SubModulo, SubModuloAssign,
};
use crate::utils::ExtendedGCD;

use super::TryInvModulo;

macro_rules! impl_modulo_ops_for_primitive {
    ($($t:ty),*) => {$(
        impl AddModulo<$t> for $t {
            type Output = $t;

            fn add_modulo(self, rhs: Self, modulus: $t) -> Self::Output {
                let r = self + rhs;
                if r >= modulus {
                    r - modulus
                } else {
                    r
                }
            }
        }

        impl AddModuloAssign<$t> for $t {
            fn add_modulo_assign(&mut self, rhs: Self, modulus: $t) {
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

            fn sub_modulo(self, rhs: Self, modulus: $t) -> Self::Output {
                if self >= rhs {
                    self - rhs
                } else {
                    modulus - rhs + self
                }
            }
        }

        impl SubModuloAssign<$t> for $t {
            fn sub_modulo_assign(&mut self, rhs: Self, modulus: $t) {
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
            fn neg_modulo(self, modulus: $t) -> Self::Output {
                modulus - self
            }
        }

        impl NegModuloAssign<$t> for $t {
            #[inline]
            fn neg_modulo_assign(&mut self, modulus: $t) {
                *self = modulus - *self;
            }
        }

        impl InvModulo for $t {
            fn inv_modulo(self, modulus: Self) -> Self {
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
            fn try_inv_modulo(self, modulus: Self) -> Result<Self, crate::Error> {
                assert!(self < modulus);

                let (_, inv, gcd) = Self::extended_gcd(modulus, self);

                if gcd == 1 {
                    if inv > 0 {
                        Ok(inv as Self)
                    } else {
                        Ok((inv + modulus as <Self as ExtendedGCD>::SignedT) as Self)
                    }
                } else {
                    Err(crate::Error::NoModuloInverse {
                        value: self.to_string(),
                        modulus: modulus.to_string(),
                    })
                }
            }
        }
    )*};
}

impl_modulo_ops_for_primitive!(u8, u16, u32, u64);

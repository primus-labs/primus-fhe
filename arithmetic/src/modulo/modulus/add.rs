use crate::modulo::{FastAddModulo, FastAddModuloAssign};

use super::Modulus;

impl FastAddModulo<&Modulus> for u64 {
    type Output = u64;

    fn add_modulo(self, rhs: Self, modulus: &Modulus) -> Self::Output {
        let r = self + rhs;
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl FastAddModuloAssign<&Modulus> for u64 {
    fn add_modulo_assign(&mut self, rhs: Self, modulus: &Modulus) {
        let r = *self + rhs;
        *self = if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        };
    }
}
use crate::modulo::{FastAddModulo, FastAddModuloAssign};

use super::PrimeModulus;

impl FastAddModulo<PrimeModulus> for u64 {
    type Output = u64;

    fn add_modulo(self, rhs: Self, modulus: PrimeModulus) -> Self::Output {
        let r = self + rhs;
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl FastAddModuloAssign<PrimeModulus> for u64 {
    fn add_modulo_assign(&mut self, rhs: Self, modulus: PrimeModulus) {
        let r = *self + rhs;
        *self = if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        };
    }
}

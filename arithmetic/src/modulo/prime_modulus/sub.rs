use crate::modulo::{FastSubModulo, FastSubModuloAssign};

use super::PrimeModulus;

impl FastSubModulo<PrimeModulus> for u64 {
    type Output = u64;

    fn sub_modulo(self, rhs: Self, modulus: PrimeModulus) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus.value() - rhs + self
        }
    }
}

impl FastSubModuloAssign<PrimeModulus> for u64 {
    fn sub_modulo_assign(&mut self, rhs: Self, modulus: PrimeModulus) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus.value() - rhs;
        }
    }
}

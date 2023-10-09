use crate::modulo::{FastSubModulo, FastSubModuloAssign};

use super::Modulus;

impl FastSubModulo<&Modulus> for u64 {
    type Output = u64;

    fn sub_modulo(self, rhs: Self, modulus: &Modulus) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus.value() - rhs + self
        }
    }
}

impl FastSubModuloAssign<&Modulus> for u64 {
    fn sub_modulo_assign(&mut self, rhs: Self, modulus: &Modulus) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus.value() - rhs;
        }
    }
}

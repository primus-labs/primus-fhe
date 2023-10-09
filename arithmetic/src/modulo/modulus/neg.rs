use crate::modulo::{NegModulo, NegModuloAssign};

use super::Modulus;

impl NegModulo<&Modulus> for u64 {
    type Output = u64;

    fn neg_modulo(self, modulus: &Modulus) -> Self::Output {
        modulus.value() - self
    }
}

impl NegModuloAssign<&Modulus> for u64 {
    fn neg_modulo_assign(&mut self, modulus: &Modulus) {
        *self = modulus.value() - *self;
    }
}

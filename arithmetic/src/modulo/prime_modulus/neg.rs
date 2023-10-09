use crate::modulo::{NegModulo, NegModuloAssign};

use super::PrimeModulus;

impl NegModulo<PrimeModulus> for u64 {
    type Output = u64;

    fn neg_modulo(self, modulus: PrimeModulus) -> Self::Output {
        modulus.value() - self
    }
}

impl NegModuloAssign<PrimeModulus> for u64 {
    fn neg_modulo_assign(&mut self, modulus: PrimeModulus) {
        *self = modulus.value() - *self;
    }
}

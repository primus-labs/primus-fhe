use std::ops::Sub;

use crate::modulo::{NegModulo, NegModuloAssign, PrimeModulus};

impl<T> NegModulo<&PrimeModulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    type Output = T;

    fn neg_modulo(self, modulus: &PrimeModulus<T>) -> Self::Output {
        modulus.value() - self
    }
}

impl<T> NegModuloAssign<&PrimeModulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    fn neg_modulo_assign(&mut self, modulus: &PrimeModulus<T>) {
        *self = modulus.value() - *self;
    }
}

use crate::modulo::{InvModulo, InvModuloAssign, PrimeModulus};

impl<T> InvModulo<&PrimeModulus<T>> for T
where
    T: Copy + InvModulo<T>,
{
    fn inv_modulo(self, modulus: &PrimeModulus<T>) -> Self {
        self.inv_modulo(modulus.value())
    }
}

impl<T> InvModuloAssign<&PrimeModulus<T>> for T
where
    T: Copy + InvModulo<T>,
{
    fn inv_modulo_assign(&mut self, modulus: &PrimeModulus<T>) {
        *self = self.inv_modulo(modulus.value());
    }
}

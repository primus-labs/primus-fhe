use crate::modulo::{
    DivModulo, DivModuloAssign, InvModulo, MulModulo, MulModuloAssign, PrimeModulus,
};

impl<T> DivModulo<&PrimeModulus<T>> for T
where
    T: for<'m> MulModulo<&'m PrimeModulus<T>, Output = T> + for<'m> InvModulo<&'m PrimeModulus<T>>,
{
    type Output = T;

    fn div_modulo(self, rhs: Self, modulus: &PrimeModulus<T>) -> Self::Output {
        self.mul_modulo(rhs.inv_modulo(modulus), modulus)
    }
}

impl<T> DivModuloAssign<&PrimeModulus<T>> for T
where
    T: for<'m> MulModuloAssign<&'m PrimeModulus<T>> + for<'m> InvModulo<&'m PrimeModulus<T>>,
{
    fn div_modulo_assign(&mut self, rhs: Self, modulus: &PrimeModulus<T>) {
        self.mul_modulo_assign(rhs.inv_modulo(modulus), modulus)
    }
}

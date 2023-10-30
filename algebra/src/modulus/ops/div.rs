use crate::modulo::{DivModulo, DivModuloAssign, InvModulo, MulModulo, MulModuloAssign};
use crate::modulus::Modulus;

impl<T> DivModulo<&Modulus<T>> for T
where
    T: for<'m> MulModulo<&'m Modulus<T>, Output = T> + for<'m> InvModulo<&'m Modulus<T>>,
{
    type Output = T;

    #[inline]
    fn div_modulo(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        self.mul_modulo(rhs.inv_modulo(modulus), modulus)
    }
}

impl<T> DivModuloAssign<&Modulus<T>> for T
where
    T: for<'m> MulModuloAssign<&'m Modulus<T>> + for<'m> InvModulo<&'m Modulus<T>>,
{
    #[inline]
    fn div_modulo_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        self.mul_modulo_assign(rhs.inv_modulo(modulus), modulus)
    }
}

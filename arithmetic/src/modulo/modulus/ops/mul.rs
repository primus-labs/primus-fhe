use crate::modulo::{Modulo, Modulus, MulModulo, MulModuloAssign};
use crate::Widening;

impl<T> MulModulo<&Modulus<T>> for T
where
    T: Widening,
    (T, T): for<'m> Modulo<&'m Modulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn mul_modulo(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        self.widen_mul(rhs).modulo(modulus)
    }
}

impl<T> MulModuloAssign<&Modulus<T>> for T
where
    T: Copy + Widening,
    (T, T): for<'m> Modulo<&'m Modulus<T>, Output = T>,
{
    #[inline]
    fn mul_modulo_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        *self = self.widen_mul(rhs).modulo(modulus);
    }
}

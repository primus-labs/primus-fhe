use crate::modulo::{Modulo, MulModulo, MulModuloAssign, PrimeModulus};
use crate::Widening;

impl<T> MulModulo<&PrimeModulus<T>> for T
where
    T: Widening,
    (T, T): for<'m> Modulo<&'m PrimeModulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn mul_modulo(self, rhs: Self, modulus: &PrimeModulus<T>) -> Self::Output {
        self.widen_mul(rhs).modulo(modulus)
    }
}

impl<T> MulModuloAssign<&PrimeModulus<T>> for T
where
    T: Copy + Widening,
    (T, T): for<'m> Modulo<&'m PrimeModulus<T>, Output = T>,
{
    #[inline]
    fn mul_modulo_assign(&mut self, rhs: Self, modulus: &PrimeModulus<T>) {
        *self = self.widen_mul(rhs).modulo(modulus);
    }
}

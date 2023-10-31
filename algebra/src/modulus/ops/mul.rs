use crate::modulo_traits::{Modulo, MulModulo, MulModuloAssign};
use crate::modulus::Modulus;
use crate::Widening;

impl<T> MulModulo<&Modulus<T>> for T
where
    T: Widening,
    (T, T): for<'m> Modulo<&'m Modulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        self.widen_mul(rhs).reduce(modulus)
    }
}

impl<T> MulModuloAssign<&Modulus<T>> for T
where
    T: Copy + Widening,
    (T, T): for<'m> Modulo<&'m Modulus<T>, Output = T>,
{
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        *self = self.widen_mul(rhs).reduce(modulus);
    }
}

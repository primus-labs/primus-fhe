use std::ops::Sub;

use crate::modulo_traits::{NegModulo, NegModuloAssign};
use crate::modulus::Modulus;

impl<T> NegModulo<&Modulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    type Output = T;

    #[inline]
    fn neg_reduce(self, modulus: &Modulus<T>) -> Self::Output {
        modulus.value() - self
    }
}

impl<T> NegModuloAssign<&Modulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    #[inline]
    fn neg_reduce_assign(&mut self, modulus: &Modulus<T>) {
        *self = modulus.value() - *self;
    }
}

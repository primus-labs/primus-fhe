use std::ops::{Add, Sub};

use crate::modulo::{AddModulo, AddModuloAssign, Modulus};

impl<T> AddModulo<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    type Output = T;

    fn add_modulo(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        let r = self + rhs;
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl<T> AddModuloAssign<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    fn add_modulo_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        let r = *self + rhs;
        *self = if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        };
    }
}

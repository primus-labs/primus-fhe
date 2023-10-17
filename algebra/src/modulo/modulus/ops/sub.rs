use std::ops::{Add, AddAssign, Sub, SubAssign};

use crate::modulo::{Modulus, SubModulo, SubModuloAssign};

impl<T> SubModulo<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    type Output = T;

    fn sub_modulo(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus.value() - rhs + self
        }
    }
}

impl<T> SubModuloAssign<&Modulus<T>> for T
where
    T: Copy + AddAssign + SubAssign + Sub<Output = Self> + PartialOrd,
{
    fn sub_modulo_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus.value() - rhs;
        }
    }
}

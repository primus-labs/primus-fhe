use std::ops::{Add, AddAssign, Sub, SubAssign};

use crate::modulo::{FastSubModulo, FastSubModuloAssign, PrimeModulus};

impl<T> FastSubModulo<&PrimeModulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    type Output = T;

    fn sub_modulo(self, rhs: Self, modulus: &PrimeModulus<T>) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus.value() - rhs + self
        }
    }
}

impl<T> FastSubModuloAssign<&PrimeModulus<T>> for T
where
    T: Copy + AddAssign + SubAssign + Sub<Output = Self> + PartialOrd,
{
    fn sub_modulo_assign(&mut self, rhs: Self, modulus: &PrimeModulus<T>) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus.value() - rhs;
        }
    }
}

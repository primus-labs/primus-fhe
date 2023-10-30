use crate::modulo::{InvModulo, InvModuloAssign};
use crate::modulus::Modulus;

impl<T> InvModulo<&Modulus<T>> for T
where
    T: Copy + InvModulo<T>,
{
    #[inline]
    fn inv_modulo(self, modulus: &Modulus<T>) -> Self {
        self.inv_modulo(modulus.value())
    }
}

impl<T> InvModuloAssign<&Modulus<T>> for T
where
    T: Copy + InvModulo<T>,
{
    #[inline]
    fn inv_modulo_assign(&mut self, modulus: &Modulus<T>) {
        *self = self.inv_modulo(modulus.value());
    }
}

#[cfg(test)]
mod tests {
    use rand::{prelude::*, thread_rng};

    use crate::{modulo::MulModulo, utils::Prime};

    use super::*;

    #[test]
    fn test_inverse() {
        type Num = u64;
        let mut rng = thread_rng();

        let mut m = rng.gen_range(2..=(u64::MAX >> 2));

        if m & 1 == 0 {
            m += 1;
        }

        let modulus = Modulus::<Num>::new(m);

        if modulus.probably_prime(20) {
            let value: u64 = rng.gen_range(2..modulus.value());
            let inv = value.inv_modulo(&modulus);
            assert_eq!(
                value.mul_modulo(inv, &modulus),
                1,
                "\nval:{value}\ninv:{inv}\nmod:{}",
                modulus.value()
            );
        }
    }
}

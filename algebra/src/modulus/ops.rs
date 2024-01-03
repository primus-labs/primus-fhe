use std::ops::{Add, AddAssign, ShrAssign, Sub, SubAssign};

use num_traits::{One, PrimInt};

use crate::modulus::Modulus;
use crate::reduce::{
    AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, InvReduce, InvReduceAssign, MulReduce,
    MulReduceAssign, NegReduce, NegReduceAssign, PowReduce, Reduce, SubReduce, SubReduceAssign,
};
use crate::{Bits, Widening};

impl<T> AddReduce<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    type Output = T;

    #[inline]
    fn add_reduce(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        let r = self + rhs;
        if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        }
    }
}

impl<T> AddReduceAssign<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    #[inline]
    fn add_reduce_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        let r = *self + rhs;
        *self = if r >= modulus.value() {
            r - modulus.value()
        } else {
            r
        };
    }
}

impl<T> SubReduce<&Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + Sub<Output = Self> + PartialOrd,
{
    type Output = T;

    #[inline]
    fn sub_reduce(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        if self >= rhs {
            self - rhs
        } else {
            modulus.value() - rhs + self
        }
    }
}

impl<T> SubReduceAssign<&Modulus<T>> for T
where
    T: Copy + AddAssign + SubAssign + Sub<Output = Self> + PartialOrd,
{
    #[inline]
    fn sub_reduce_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        if *self >= rhs {
            *self -= rhs;
        } else {
            *self += modulus.value() - rhs;
        }
    }
}

impl<T> NegReduce<&Modulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    type Output = T;

    #[inline]
    fn neg_reduce(self, modulus: &Modulus<T>) -> Self::Output {
        modulus.value() - self
    }
}

impl<T> NegReduceAssign<&Modulus<T>> for T
where
    T: Copy + Sub<Output = Self>,
{
    #[inline]
    fn neg_reduce_assign(&mut self, modulus: &Modulus<T>) {
        *self = modulus.value() - *self;
    }
}

impl<T> MulReduce<&Modulus<T>> for T
where
    T: Widening,
    (T, T): for<'m> Reduce<&'m Modulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        self.widen_mul(rhs).reduce(modulus)
    }
}

impl<T> MulReduceAssign<&Modulus<T>> for T
where
    T: Copy + Widening,
    (T, T): for<'m> Reduce<&'m Modulus<T>, Output = T>,
{
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        *self = self.widen_mul(rhs).reduce(modulus);
    }
}

impl<T, E> PowReduce<&Modulus<T>, E> for T
where
    T: Copy + One + PartialOrd + for<'m> MulReduce<&'m Modulus<T>, Output = T>,
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn pow_reduce(self, mut exp: E, modulus: &Modulus<T>) -> Self {
        if exp.is_zero() {
            return Self::one();
        }

        debug_assert!(self < modulus.value());

        let mut power: Self = self;

        let exp_trailing_zeros = exp.trailing_zeros();
        if exp_trailing_zeros > 0 {
            for _ in 0..exp_trailing_zeros {
                power = power.mul_reduce(power, modulus);
            }
            exp >>= exp_trailing_zeros;
        }

        if exp.is_one() {
            return power;
        }

        let mut intermediate: Self = power;
        for _ in 1..(E::N_BITS - exp.leading_zeros()) {
            exp >>= 1;
            power = power.mul_reduce(power, modulus);
            if !(exp & E::one()).is_zero() {
                intermediate = intermediate.mul_reduce(power, modulus);
            }
        }
        intermediate
    }
}

impl<T> InvReduce<&Modulus<T>> for T
where
    T: Copy + InvReduce<T>,
{
    #[inline]
    fn inv_reduce(self, modulus: &Modulus<T>) -> Self {
        self.inv_reduce(modulus.value())
    }
}

impl<T> InvReduceAssign<&Modulus<T>> for T
where
    T: Copy + InvReduce<T>,
{
    #[inline]
    fn inv_reduce_assign(&mut self, modulus: &Modulus<T>) {
        *self = self.inv_reduce(modulus.value());
    }
}

impl<T> DivReduce<&Modulus<T>> for T
where
    T: for<'m> MulReduce<&'m Modulus<T>, Output = T> + for<'m> InvReduce<&'m Modulus<T>>,
{
    type Output = T;

    #[inline]
    fn div_reduce(self, rhs: Self, modulus: &Modulus<T>) -> Self::Output {
        self.mul_reduce(rhs.inv_reduce(modulus), modulus)
    }
}

impl<T> DivReduceAssign<&Modulus<T>> for T
where
    T: for<'m> MulReduceAssign<&'m Modulus<T>> + for<'m> InvReduce<&'m Modulus<T>>,
{
    #[inline]
    fn div_reduce_assign(&mut self, rhs: Self, modulus: &Modulus<T>) {
        self.mul_reduce_assign(rhs.inv_reduce(modulus), modulus);
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use rand::{prelude::*, thread_rng};

    use crate::utils::Prime;

    use super::*;

    type T = u32;
    type W = u64;

    #[test]
    fn test_pow_mod_simple() {
        const P: T = 1000000513;
        let modulus = Modulus::<T>::new(P);

        let distr = rand::distributions::Uniform::new_inclusive(0, P - 1);
        let mut rng = thread_rng();

        for _ in 0..5 {
            let base = rng.sample(distr);
            let exp = random();

            assert_eq!(simple_pow(base, exp, P), base.pow_reduce(exp, &modulus));
        }
    }

    fn simple_pow(base: T, mut exp: u32, modulus: T) -> T {
        if exp.is_zero() {
            return 1;
        }

        debug_assert!(base < modulus);

        if exp.is_one() {
            return base;
        }

        let mut power: T = base;
        let mut intermediate: T = 1;
        loop {
            if exp & 1 != 0 {
                intermediate = ((intermediate as W * power as W) % modulus as W) as T;
            }
            exp >>= 1;
            if exp.is_zero() {
                break;
            }
            power = ((power as W * power as W) % modulus as W) as T;
        }
        intermediate
    }

    #[test]
    fn test_inverse() {
        type Num = u64;
        let mut rng = thread_rng();

        let mut m = rng.gen_range(2..=(Num::MAX >> 2));

        if m & 1 == 0 {
            m |= 1;
        }

        let modulus = Modulus::<Num>::new(m);

        if modulus.probably_prime(20) {
            let value: Num = rng.gen_range(2..modulus.value());
            let inv: Num = value.inv_reduce(&modulus);
            assert_eq!(
                value.mul_reduce(inv, &modulus),
                1,
                "\nval:{value}\ninv:{inv}\nmod:{}",
                modulus.value()
            );
        }
    }
}

use std::ops::ShrAssign;

use num_traits::{One, PrimInt};

use crate::modulus::BarrettModulus;
use crate::reduce::{
    AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, ExpPowOf2Reduce, ExpReduce, InvReduce,
    InvReduceAssign, LazyMulReduce, LazyMulReduceAssign, LazyReduce, MulReduce, MulReduceAssign,
    NegReduce, NegReduceAssign, Reduce, SubReduce, SubReduceAssign,
};
use crate::{Bits, Widening};

impl<T> AddReduce<BarrettModulus<T>> for T
where
    T: Copy + AddReduce<T, Output = T>,
{
    type Output = T;

    #[inline]
    fn add_reduce(self, rhs: Self, modulus: BarrettModulus<T>) -> Self::Output {
        self.add_reduce(rhs, modulus.value())
    }
}

impl<T> AddReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + AddReduceAssign<T>,
{
    #[inline]
    fn add_reduce_assign(&mut self, rhs: Self, modulus: BarrettModulus<T>) {
        self.add_reduce_assign(rhs, modulus.value());
    }
}

impl<T> SubReduce<BarrettModulus<T>> for T
where
    T: Copy + SubReduce<T, Output = T>,
{
    type Output = T;

    #[inline]
    fn sub_reduce(self, rhs: Self, modulus: BarrettModulus<T>) -> Self::Output {
        self.sub_reduce(rhs, modulus.value())
    }
}

impl<T> SubReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + SubReduceAssign<T>,
{
    #[inline]
    fn sub_reduce_assign(&mut self, rhs: Self, modulus: BarrettModulus<T>) {
        self.sub_reduce_assign(rhs, modulus.value());
    }
}

impl<T> NegReduce<BarrettModulus<T>> for T
where
    T: Copy + NegReduce<T, Output = T>,
{
    type Output = T;

    #[inline]
    fn neg_reduce(self, modulus: BarrettModulus<T>) -> Self::Output {
        self.neg_reduce(modulus.value())
    }
}

impl<T> NegReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + NegReduceAssign<T>,
{
    #[inline]
    fn neg_reduce_assign(&mut self, modulus: BarrettModulus<T>) {
        self.neg_reduce_assign(modulus.value());
    }
}

impl<T> MulReduce<BarrettModulus<T>> for T
where
    T: Copy + Widening,
    (T, T): Reduce<BarrettModulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, modulus: BarrettModulus<T>) -> Self::Output {
        self.widening_mul(rhs).reduce(modulus)
    }
}

impl<T> MulReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + Widening,
    (T, T): Reduce<BarrettModulus<T>, Output = T>,
{
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, modulus: BarrettModulus<T>) {
        *self = self.widening_mul(rhs).reduce(modulus);
    }
}

impl<T, E> ExpReduce<BarrettModulus<T>, E> for T
where
    T: Copy + One + PartialOrd + MulReduce<BarrettModulus<T>, Output = T>,
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn exp_reduce(self, mut exp: E, modulus: BarrettModulus<T>) -> Self {
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
        for _ in 1..(E::BITS - exp.leading_zeros()) {
            exp >>= 1;
            power = power.mul_reduce(power, modulus);
            if !(exp & E::one()).is_zero() {
                intermediate = intermediate.mul_reduce(power, modulus);
            }
        }
        intermediate
    }
}

impl<T> ExpPowOf2Reduce<BarrettModulus<T>> for T
where
    T: Copy + One + PartialOrd + MulReduce<BarrettModulus<T>, Output = T>,
{
    #[inline]
    fn exp_power_of_2_reduce(self, exp_log: u32, modulus: BarrettModulus<T>) -> Self {
        let mut power: Self = self;

        for _ in 0..exp_log {
            power = power.mul_reduce(power, modulus);
        }

        power
    }
}

impl<T> InvReduce<BarrettModulus<T>> for T
where
    T: Copy + InvReduce<T>,
{
    #[inline]
    fn inv_reduce(self, modulus: BarrettModulus<T>) -> Self {
        self.inv_reduce(modulus.value())
    }
}

impl<T> InvReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + InvReduce<T>,
{
    #[inline]
    fn inv_reduce_assign(&mut self, modulus: BarrettModulus<T>) {
        *self = self.inv_reduce(modulus.value());
    }
}

impl<T> DivReduce<BarrettModulus<T>> for T
where
    T: Copy + MulReduce<BarrettModulus<T>, Output = T> + InvReduce<BarrettModulus<T>>,
{
    type Output = T;

    #[inline]
    fn div_reduce(self, rhs: Self, modulus: BarrettModulus<T>) -> Self::Output {
        self.mul_reduce(rhs.inv_reduce(modulus), modulus)
    }
}

impl<T> DivReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + MulReduceAssign<BarrettModulus<T>> + InvReduce<BarrettModulus<T>>,
{
    #[inline]
    fn div_reduce_assign(&mut self, rhs: Self, modulus: BarrettModulus<T>) {
        self.mul_reduce_assign(rhs.inv_reduce(modulus), modulus);
    }
}

impl<T> LazyMulReduce<BarrettModulus<T>> for T
where
    T: Copy + Widening,
    (T, T): LazyReduce<BarrettModulus<T>, Output = T>,
{
    type Output = Self;

    #[inline]
    fn lazy_mul_reduce(self, rhs: Self, modulus: BarrettModulus<T>) -> Self::Output {
        self.widening_mul(rhs).lazy_reduce(modulus)
    }
}

impl<T> LazyMulReduceAssign<BarrettModulus<T>> for T
where
    T: Copy + Widening,
    (T, T): LazyReduce<BarrettModulus<T>, Output = T>,
{
    #[inline]
    fn lazy_mul_reduce_assign(&mut self, rhs: Self, modulus: BarrettModulus<T>) {
        *self = self.widening_mul(rhs).lazy_reduce(modulus);
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use rand::prelude::*;

    use crate::utils::Prime;

    use super::*;

    type T = u32;
    type W = u64;

    #[test]
    fn test_pow_mod_simple() {
        const P: T = 1000000513;
        let modulus = BarrettModulus::<T>::new(P);

        let distr = rand::distributions::Uniform::new_inclusive(0, P - 1);
        let mut rng = thread_rng();

        for _ in 0..5 {
            let base = rng.sample(distr);
            let exp = random();

            assert_eq!(simple_pow(base, exp, P), base.exp_reduce(exp, modulus));
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

        let modulus = BarrettModulus::<Num>::new(m);

        if modulus.probably_prime(20) {
            let value: Num = rng.gen_range(2..modulus.value());
            let inv: Num = value.inv_reduce(modulus);
            assert_eq!(
                value.mul_reduce(inv, modulus),
                1,
                "\nval:{value}\ninv:{inv}\nmod:{}",
                modulus.value()
            );
        }
    }
}

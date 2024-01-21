use std::ops::{Add, BitAnd, BitXor, Mul, ShrAssign, Sub};

use num_traits::{One, PrimInt};

use crate::{
    reduce::{
        AddReduce, AddReduceAssign, MulReduce, MulReduceAssign, NegReduce, NegReduceAssign,
        PowReduce, SubReduce, SubReduceAssign,
    },
    Bits,
};

use super::PowOf2Modulus;

impl<T> AddReduce<PowOf2Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + BitAnd<Output = Self>,
{
    type Output = T;

    #[inline]
    fn add_reduce(self, rhs: Self, modulus: PowOf2Modulus<T>) -> Self::Output {
        (self + rhs) & modulus.mask()
    }
}

impl<T> AddReduceAssign<PowOf2Modulus<T>> for T
where
    T: Copy + Add<Output = Self> + BitAnd<Output = Self>,
{
    #[inline]
    fn add_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<T>) {
        *self = (*self + rhs) & modulus.mask();
    }
}

impl<T> SubReduce<PowOf2Modulus<T>> for T
where
    T: Copy + Sub<Output = Self> + BitAnd<Output = Self>,
{
    type Output = T;

    #[inline]
    fn sub_reduce(self, rhs: Self, modulus: PowOf2Modulus<T>) -> Self::Output {
        (self - rhs) & modulus.mask()
    }
}

impl<T> SubReduceAssign<PowOf2Modulus<T>> for T
where
    T: Copy + Sub<Output = Self> + BitAnd<Output = Self>,
{
    #[inline]
    fn sub_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<T>) {
        *self = (*self - rhs) & modulus.mask();
    }
}

impl<T> NegReduce<PowOf2Modulus<T>> for T
where
    T: Copy + Sub<Output = Self> + BitXor<Output = Self>,
{
    type Output = T;

    #[inline]
    fn neg_reduce(self, modulus: PowOf2Modulus<T>) -> Self::Output {
        self ^ modulus.mask()
    }
}

impl<T> NegReduceAssign<PowOf2Modulus<T>> for T
where
    T: Copy + Sub<Output = Self> + BitXor<Output = Self>,
{
    #[inline]
    fn neg_reduce_assign(&mut self, modulus: PowOf2Modulus<T>) {
        *self = *self ^ modulus.mask();
    }
}

impl<T> MulReduce<PowOf2Modulus<T>> for T
where
    T: Copy + Mul<Output = Self> + BitAnd<Output = Self>,
{
    type Output = Self;

    #[inline]
    fn mul_reduce(self, rhs: Self, modulus: PowOf2Modulus<T>) -> Self::Output {
        (self * rhs) & modulus.mask()
    }
}

impl<T> MulReduceAssign<PowOf2Modulus<T>> for T
where
    T: Copy + Mul<Output = Self> + BitAnd<Output = Self>,
{
    #[inline]
    fn mul_reduce_assign(&mut self, rhs: Self, modulus: PowOf2Modulus<T>) {
        *self = (*self * rhs) & modulus.mask();
    }
}

impl<T, E> PowReduce<PowOf2Modulus<T>, E> for T
where
    T: Copy + One + PartialOrd + MulReduce<PowOf2Modulus<T>, Output = T>,
    E: PrimInt + ShrAssign<u32> + Bits,
{
    fn pow_reduce(self, mut exp: E, modulus: PowOf2Modulus<T>) -> Self {
        if exp.is_zero() {
            return Self::one();
        }

        debug_assert!(self <= modulus.mask());

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

mod extension;

use std::{
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_traits::{Inv, One, Pow, Zero};

use crate::{
    div_ceil,
    modulus::{self, to_canonical_u64, GoldilocksModulus},
    reduce::{
        AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, InvReduce, MulReduce,
        MulReduceAssign, NegReduce, PowReduce, SubReduce, SubReduceAssign,
    },
    Field, PrimeField,
};

/// Implementation of Goldilocks field
#[derive(Debug, Default, Clone, Copy)]
pub struct Goldilocks(u64);

impl Field for Goldilocks {
    type Order = u64;

    type Value = u64;

    const MODULUS_VALUE: Self::Value = modulus::GOLDILOCKS_P;

    #[inline]
    fn neg_one() -> Self {
        Self(modulus::GOLDILOCKS_P - 1)
    }

    #[inline]
    fn lazy_new(value: Self::Value) -> Self {
        Self(value)
    }

    #[inline]
    fn new(value: Self::Value) -> Self {
        Self(value)
    }

    #[inline]
    fn value(self) -> Self::Value {
        to_canonical_u64(self.0)
    }

    #[inline]
    fn mul_scalar(self, scalar: Self::Value) -> Self {
        Self(self.0.mul_reduce(scalar, GoldilocksModulus))
    }

    #[inline]
    fn add_mul(self, a: Self, b: Self) -> Self {
        self + a * b
    }

    #[inline]
    fn add_mul_fast(self, a: Self, b: Self) -> Self {
        self + a * b
    }

    #[inline]
    fn add_mul_assign(&mut self, a: Self, b: Self) {
        *self += a * b;
    }

    #[inline]
    fn add_mul_assign_fast(&mut self, a: Self, b: Self) {
        *self += a * b;
    }

    #[inline]
    fn mul_fast(self, rhs: Self) -> Self {
        self * rhs
    }

    #[inline]
    fn mul_assign_fast(&mut self, rhs: Self) {
        *self *= rhs;
    }

    #[inline]
    fn mask(bits: u32) -> Self::Value {
        u64::MAX >> (u64::BITS - bits)
    }

    #[inline]
    fn decompose_len(basis: Self::Value) -> usize {
        debug_assert!(basis.is_power_of_two() && basis > 1);
        div_ceil(
            64 - Self::MODULUS_VALUE.leading_zeros(),
            basis.trailing_zeros(),
        ) as usize
    }

    #[inline]
    fn decompose(self, basis: crate::Basis<Self>) -> Vec<Self> {
        let mut temp = self.value();

        let len = basis.decompose_len();
        let mask = basis.mask();
        let bits = basis.bits();

        let mut ret: Vec<Self> = vec![Self::zero(); len];

        for v in ret.iter_mut() {
            if temp == 0 {
                break;
            }
            *v = Self(temp & mask);
            temp >>= bits;
        }

        ret
    }

    #[inline]
    fn decompose_at(self, basis: crate::Basis<Self>, destination: &mut [Self]) {
        let mut temp = self.value();

        let mask = basis.mask();
        let bits = basis.bits();

        for v in destination {
            if temp == 0 {
                break;
            }
            *v = Self(temp & mask);
            temp >>= bits;
        }
    }

    #[inline]
    fn decompose_lsb_bits(&mut self, mask: Self::Value, bits: u32) -> Self {
        let value = self.value();
        let temp = Self(value & mask);
        *self = Self(value >> bits);
        temp
    }

    #[inline]
    fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Value, bits: u32) {
        let value = self.value();
        *destination = Self(value & mask);
        *self = Self(value >> bits);
    }
}

impl Display for Goldilocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add<Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Mul<Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Sub<Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Div<Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, GoldilocksModulus))
    }
}

impl AddAssign<Self> for Goldilocks {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl SubAssign<Self> for Goldilocks {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl MulAssign<Self> for Goldilocks {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0.mul_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl DivAssign<Self> for Goldilocks {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0.div_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl Add<&Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Sub<&Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Mul<&Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, GoldilocksModulus))
    }
}

impl Div<&Self> for Goldilocks {
    type Output = Self;
    #[inline]
    fn div(self, rhs: &Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, GoldilocksModulus))
    }
}

impl AddAssign<&Self> for Goldilocks {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl SubAssign<&Self> for Goldilocks {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl MulAssign<&Self> for Goldilocks {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0.mul_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl DivAssign<&Self> for Goldilocks {
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        self.0.div_reduce_assign(rhs.0, GoldilocksModulus);
    }
}

impl PartialEq for Goldilocks {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

impl Eq for Goldilocks {}

impl PartialOrd for Goldilocks {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Goldilocks {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

impl Neg for Goldilocks {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg_reduce(GoldilocksModulus))
    }
}

impl Inv for Goldilocks {
    type Output = Self;
    #[inline]
    fn inv(self) -> Self::Output {
        Self(self.0.inv_reduce(GoldilocksModulus))
    }
}

impl Pow<u64> for Goldilocks {
    type Output = Self;
    #[inline]
    fn pow(self, rhs: u64) -> Self::Output {
        Self(self.0.pow_reduce(rhs, GoldilocksModulus))
    }
}

impl Zero for Goldilocks {
    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self(0)
    }

    #[inline]
    fn set_zero(&mut self) {
        *self = Self(0);
    }

    #[inline]
    fn zero() -> Self {
        Self(0)
    }
}

impl One for Goldilocks {
    #[inline]
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self(1)
    }

    #[inline]
    fn set_one(&mut self) {
        *self = Self(1);
    }

    #[inline]
    fn one() -> Self {
        Self(1)
    }
}

impl PrimeField for Goldilocks {
    #[inline]
    fn is_prime_field() -> bool {
        true
    }
}

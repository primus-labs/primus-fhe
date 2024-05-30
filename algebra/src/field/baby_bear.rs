use std::{
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_traits::{Inv, One, Pow, Zero};

use crate::{
    div_ceil,
    modulus::{
        self,
        baby_bear::{from_monty, to_monty, MONTY_NEG_ONE, MONTY_ONE, MONTY_ZERO},
        BabyBearModulus,
    },
    reduce::{
        AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, InvReduce, MulReduce,
        MulReduceAssign, NegReduce, PowReduce, SubReduce, SubReduceAssign,
    },
    Field, PrimeField,
};

/// Implementation of BabyBear field.
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct BabyBear(u32);

impl Field for BabyBear {
    type Value = u32;

    type Order = u32;

    const ONE: Self = BabyBear(MONTY_ONE);

    const ZERO: Self = BabyBear(MONTY_ZERO);

    const NEG_ONE: Self = BabyBear(MONTY_NEG_ONE);

    const MODULUS_VALUE: Self::Value = modulus::baby_bear::P;

    #[inline]
    fn lazy_new(value: Self::Value) -> Self {
        BabyBear(to_monty(value))
    }

    #[inline]
    fn new(value: Self::Value) -> Self {
        Self::lazy_new(value)
    }

    #[inline]
    fn value(self) -> Self::Value {
        from_monty(self.0)
    }

    #[inline]
    fn mul_scalar(self, scalar: Self::Value) -> Self {
        Self(self.0.mul_reduce(to_monty(scalar), BabyBearModulus))
    }

    #[inline]
    fn add_mul(self, a: Self, b: Self) -> Self {
        self + a * b
    }

    #[inline]
    fn add_mul_assign(&mut self, a: Self, b: Self) {
        *self += a * b;
    }

    #[inline]
    fn add_mul_assign_fast(&mut self, a: Self, b: Self) {
        self.add_mul_assign(a, b);
    }

    #[inline]
    fn add_mul_fast(self, a: Self, b: Self) -> Self {
        self.add_mul(a, b)
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
        u32::MAX >> (u32::BITS - bits)
    }

    #[inline]
    fn decompose_len(basis: Self::Value) -> usize {
        debug_assert!(basis.is_power_of_two() && basis > 1);
        div_ceil(
            32 - Self::MODULUS_VALUE.leading_zeros(),
            basis.trailing_zeros(),
        ) as usize
    }

    #[inline]
    fn decompose(self, basis: crate::Basis<Self>) -> Vec<Self> {
        let mut temp = self.value();

        let len = basis.decompose_len();
        let mask = basis.mask();
        let bits = basis.bits();

        let mut ret: Vec<Self> = vec![Self::ZERO; len];

        for v in ret.iter_mut() {
            if temp == 0 {
                break;
            }
            *v = Self::new(temp & mask);
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
            *v = Self::new(temp & mask);
            temp >>= bits;
        }
    }

    #[inline]
    fn decompose_lsb_bits(&mut self, mask: Self::Value, bits: u32) -> Self {
        let value = self.value();
        let temp = Self::new(value & mask);
        *self = Self::new(value >> bits);
        temp
    }

    #[inline]
    fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Value, bits: u32) {
        let value = self.value();
        *destination = Self::new(value & mask);
        *self = Self::new(value >> bits);
    }
}

impl Display for BabyBear {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add<Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add_reduce(rhs.0, BabyBearModulus))
    }
}

impl Mul<Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, BabyBearModulus))
    }
}

impl Sub<Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, BabyBearModulus))
    }
}

impl Div<Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, BabyBearModulus))
    }
}

impl AddAssign<Self> for BabyBear {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl SubAssign<Self> for BabyBear {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl MulAssign<Self> for BabyBear {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0.mul_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl DivAssign<Self> for BabyBear {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        self.0.div_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl Add<&Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add_reduce(rhs.0, BabyBearModulus))
    }
}

impl Sub<&Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub_reduce(rhs.0, BabyBearModulus))
    }
}

impl Mul<&Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(self.0.mul_reduce(rhs.0, BabyBearModulus))
    }
}

impl Div<&Self> for BabyBear {
    type Output = Self;
    #[inline]
    fn div(self, rhs: &Self) -> Self::Output {
        Self(self.0.div_reduce(rhs.0, BabyBearModulus))
    }
}

impl AddAssign<&Self> for BabyBear {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0.add_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl SubAssign<&Self> for BabyBear {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0.sub_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl MulAssign<&Self> for BabyBear {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0.mul_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl DivAssign<&Self> for BabyBear {
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        self.0.div_reduce_assign(rhs.0, BabyBearModulus);
    }
}

impl Neg for BabyBear {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.neg_reduce(BabyBearModulus))
    }
}

impl Inv for BabyBear {
    type Output = Self;
    #[inline]
    fn inv(self) -> Self::Output {
        Self(self.0.inv_reduce(BabyBearModulus))
    }
}

impl Pow<u32> for BabyBear {
    type Output = Self;
    #[inline]
    fn pow(self, rhs: u32) -> Self::Output {
        Self(self.0.pow_reduce(rhs, BabyBearModulus))
    }
}

impl Zero for BabyBear {
    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    #[inline]
    fn set_zero(&mut self) {
        *self = Self::ZERO;
    }

    #[inline]
    fn zero() -> Self {
        Self::ZERO
    }
}

impl One for BabyBear {
    #[inline]
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::ONE
    }

    #[inline]
    fn set_one(&mut self) {
        *self = Self::ONE;
    }

    #[inline]
    fn one() -> Self {
        Self::ONE
    }
}

impl PrimeField for BabyBear {
    fn is_prime_field() -> bool {
        true
    }
}

#[test]
fn new_test() {
    let a = 10;
    let b = from_monty(to_monty(a));

    println!("a: {}", a);
    println!("b: {}", b);
}

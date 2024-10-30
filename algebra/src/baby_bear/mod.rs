mod babybear_ntt;
mod extension;

pub use extension::BabyBearExetension;

use serde::{Deserialize, Serialize};

use std::{
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_traits::{ConstOne, ConstZero, Inv, One, Pow, Zero};

use crate::{
    modulus::{
        from_monty, to_monty, BabyBearModulus, BABY_BEAR_P, MONTY_NEG_ONE, MONTY_ONE, MONTY_ZERO,
    },
    reduce::{
        AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, ExpReduce, InvReduce, MulReduce,
        MulReduceAssign, NegReduce, SubReduce, SubReduceAssign,
    },
    ConstNegOne, DecomposableField, FheField, Field, NegOne, Packable, PrimeField, TwoAdicField,
};

/// Implementation of BabyBear field.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Hash)]
pub struct BabyBear(u32);

impl Field for BabyBear {
    type Value = u32;
    type Order = u32;

    const MODULUS_VALUE: Self::Value = BABY_BEAR_P;

    #[inline]
    fn new(value: Self::Value) -> Self {
        Self(to_monty(value))
    }

    #[inline]
    fn value(self) -> Self::Value {
        from_monty(self.0)
    }
}

impl PartialOrd for BabyBear {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.value().cmp(&other.value()))
    }

    fn lt(&self, other: &Self) -> bool {
        self.value() < other.value()
    }
}

impl Ord for BabyBear {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

impl DecomposableField for BabyBear {
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

impl FheField for BabyBear {
    #[inline]
    fn lazy_new(value: Self::Value) -> Self {
        BabyBear(to_monty(value))
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
        Self(self.0.exp_reduce(rhs, BabyBearModulus))
    }
}

impl Zero for BabyBear {
    #[inline]
    fn zero() -> Self {
        Self(MONTY_ZERO)
    }

    #[inline]
    fn set_zero(&mut self) {
        self.0 = MONTY_ZERO;
    }

    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self(MONTY_ZERO)
    }
}

impl ConstZero for BabyBear {
    const ZERO: Self = Self(MONTY_ZERO);
}

impl One for BabyBear {
    #[inline]
    fn one() -> Self {
        Self(MONTY_ONE)
    }

    #[inline]
    fn set_one(&mut self) {
        self.0 = MONTY_ONE;
    }

    #[inline]
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self(MONTY_ONE)
    }
}

impl ConstOne for BabyBear {
    const ONE: Self = Self(MONTY_ONE);
}

impl NegOne for BabyBear {
    #[inline(always)]
    fn neg_one() -> Self {
        Self(MONTY_NEG_ONE)
    }

    fn set_neg_one(&mut self) {
        self.0 = MONTY_NEG_ONE;
    }

    fn is_neg_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self(MONTY_NEG_ONE)
    }
}

impl ConstNegOne for BabyBear {
    const NEG_ONE: Self = Self(MONTY_NEG_ONE);
}

impl PrimeField for BabyBear {
    fn is_prime_field() -> bool {
        true
    }
}

impl Packable for BabyBear {}

impl TwoAdicField for BabyBear {
    const TWO_ADICITY: usize = 27;

    fn two_adic_generator(bits: usize) -> Self {
        assert!(bits <= Self::TWO_ADICITY);
        match bits {
            0 => Self::one(),
            1 => Self(to_monty(0x78000000)),
            2 => Self(to_monty(0x67055c21)),
            3 => Self(to_monty(0x5ee99486)),
            4 => Self(to_monty(0xbb4c4e4)),
            5 => Self(to_monty(0x2d4cc4da)),
            6 => Self(to_monty(0x669d6090)),
            7 => Self(to_monty(0x17b56c64)),
            8 => Self(to_monty(0x67456167)),
            9 => Self(to_monty(0x688442f9)),
            10 => Self(to_monty(0x145e952d)),
            11 => Self(to_monty(0x4fe61226)),
            12 => Self(to_monty(0x4c734715)),
            13 => Self(to_monty(0x11c33e2a)),
            14 => Self(to_monty(0x62c3d2b1)),
            15 => Self(to_monty(0x77cad399)),
            16 => Self(to_monty(0x54c131f4)),
            17 => Self(to_monty(0x4cabd6a6)),
            18 => Self(to_monty(0x5cf5713f)),
            19 => Self(to_monty(0x3e9430e8)),
            20 => Self(to_monty(0xba067a3)),
            21 => Self(to_monty(0x18adc27d)),
            22 => Self(to_monty(0x21fd55bc)),
            23 => Self(to_monty(0x4b859b3d)),
            24 => Self(to_monty(0x3bd57996)),
            25 => Self(to_monty(0x4483d85a)),
            26 => Self(to_monty(0x3a26eef8)),
            27 => Self(to_monty(0x1a427a41)),
            _ => unreachable!("Already asserted that bits <= Self::TWO_ADICITY"),
        }
    }
}

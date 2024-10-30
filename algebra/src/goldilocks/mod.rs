mod extension;
mod goldilocks_ntt;

pub use extension::GoldilocksExtension;
use serde::{Deserialize, Serialize};

use std::{
    fmt::Display,
    hash::Hash,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_traits::{ConstOne, ConstZero, Inv, One, Pow, Zero};

use crate::{
    modulus::{to_canonical_u64, GoldilocksModulus, GOLDILOCKS_P},
    reduce::{
        AddReduce, AddReduceAssign, DivReduce, DivReduceAssign, ExpReduce, InvReduce, MulReduce,
        MulReduceAssign, NegReduce, SubReduce, SubReduceAssign,
    },
    ConstNegOne, DecomposableField, FheField, Field, NegOne, Packable, PrimeField, TwoAdicField,
};

/// Implementation of Goldilocks field
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Goldilocks(u64);

impl Goldilocks {
    #[inline]
    fn as_canonical_u64(&self) -> u64 {
        let mut c = self.0;
        // We only need one condition subtraction, since 2 * ORDER would not fit in a u64.
        if c >= GOLDILOCKS_P {
            c -= GOLDILOCKS_P;
        }
        c
    }
}

impl Field for Goldilocks {
    type Value = u64;
    type Order = u64;

    const MODULUS_VALUE: Self::Value = GOLDILOCKS_P;

    #[inline]
    fn new(value: Self::Value) -> Self {
        Self(value)
    }

    #[inline]
    fn value(self) -> Self::Value {
        to_canonical_u64(self.0)
    }
}

impl DecomposableField for Goldilocks {
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

impl FheField for Goldilocks {}

impl Display for Goldilocks {
    #[inline]
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
        self.as_canonical_u64() == other.as_canonical_u64()
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
        self.as_canonical_u64().cmp(&other.as_canonical_u64())
    }
}

impl Hash for Goldilocks {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_canonical_u64().hash(state);
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
        Self(self.0.exp_reduce(rhs, GoldilocksModulus))
    }
}

impl Zero for Goldilocks {
    #[inline]
    fn zero() -> Self {
        Self(0)
    }

    #[inline]
    fn set_zero(&mut self) {
        self.0 = 0;
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl ConstZero for Goldilocks {
    const ZERO: Self = Self(0);
}

impl One for Goldilocks {
    #[inline]
    fn one() -> Self {
        Self(1)
    }

    #[inline]
    fn set_one(&mut self) {
        self.0 = 1;
    }

    #[inline]
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self(1)
    }
}

impl ConstOne for Goldilocks {
    const ONE: Self = Self(1);
}

impl NegOne for Goldilocks {
    fn neg_one() -> Self {
        Self(GOLDILOCKS_P - 1)
    }

    fn set_neg_one(&mut self) {
        self.0 = GOLDILOCKS_P - 1;
    }

    fn is_neg_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::neg_one()
    }
}

impl ConstNegOne for Goldilocks {
    const NEG_ONE: Self = Self(GOLDILOCKS_P - 1);
}

impl PrimeField for Goldilocks {
    #[inline]
    fn is_prime_field() -> bool {
        true
    }
}

impl Packable for Goldilocks {}

impl TwoAdicField for Goldilocks {
    const TWO_ADICITY: usize = 32;

    fn two_adic_generator(bits: usize) -> Self {
        // TODO: Consider a `match` which may speed this up.
        assert!(bits <= Self::TWO_ADICITY);
        let base = Self(1_753_635_133_440_165_772); // generates the whole 2^TWO_ADICITY group
        exp_power_of_2(base, Self::TWO_ADICITY - bits)
    }
}

#[must_use]
fn exp_power_of_2<F: Field>(x: F, power_log: usize) -> F {
    let mut res = x;
    for _ in 0..power_log {
        res = res * res;
    }
    res
}

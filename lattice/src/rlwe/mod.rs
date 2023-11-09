use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::field::NTTField;
use algebra::polynomial::{NTTPolynomial, Polynomial};

mod coef;
mod ntt;

pub use {coef::RlweModeCoef, ntt::RlweModeNTT};

/// A generic rlwe struct type.
#[derive(Clone)]
pub enum Rlwe<F: NTTField> {
    CoefMode(RlweModeCoef<F>),
    NttMode(RlweModeNTT<F>),
}

impl<F: NTTField> Rlwe<F> {
    #[inline]
    pub fn from_coef_mode(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self::CoefMode(RlweModeCoef { a, b })
    }

    #[inline]
    pub fn from_ntt_mode(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self::NttMode(RlweModeNTT { a, b })
    }
}

macro_rules! binary_op {
    ($left:ident, $right:ident, $op:tt) => {
        // prefer ntt mode
        match ($left, $right) {
            (Rlwe::NttMode(c0), Rlwe::NttMode(c1)) => Rlwe::NttMode(c0 $op c1),
            (Rlwe::CoefMode(c0), Rlwe::CoefMode(c1)) => Rlwe::CoefMode(c0 $op c1),
            (Rlwe::CoefMode(c0), Rlwe::NttMode(c1)) => {
                let c0: RlweModeNTT<F> = c0.into();
                Rlwe::NttMode(c0 $op c1)
            }
            (Rlwe::NttMode(c0), Rlwe::CoefMode(c1)) => {
                let c1: RlweModeNTT<F> = c1.into();
                Rlwe::NttMode(c0 $op c1)
            }
        }
    };
}

macro_rules! assign_op {
    ($left:ident, $right:ident, $assign_method:ident) => {
        match ($left, $right) {
            (Rlwe::NttMode(c0), Rlwe::NttMode(c1)) => c0.$assign_method(c1),
            (Rlwe::CoefMode(c0), Rlwe::CoefMode(c1)) => c0.$assign_method(c1),
            (Rlwe::CoefMode(c0), Rlwe::NttMode(c1)) => {
                let c1: RlweModeCoef<F> = c1.into();
                c0.$assign_method(c1)
            }
            (Rlwe::NttMode(c0), Rlwe::CoefMode(c1)) => {
                let c1: RlweModeNTT<F> = c1.into();
                c0.$assign_method(c1)
            }
        }
    };
}

impl<F: NTTField> Add<Self> for Rlwe<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        binary_op!(self, rhs, +)
    }
}

impl<F: NTTField> Add<&Self> for Rlwe<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        binary_op!(self, rhs, +)
    }
}

impl<F: NTTField> Sub<Self> for Rlwe<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        binary_op!(self, rhs, -)
    }
}

impl<F: NTTField> Sub<&Self> for Rlwe<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        binary_op!(self, rhs, -)
    }
}

impl<F: NTTField> Mul<Self> for Rlwe<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        binary_op!(self, rhs, *)
    }
}

impl<F: NTTField> Mul<&Self> for Rlwe<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        binary_op!(self, rhs, *)
    }
}

impl<F: NTTField> AddAssign<Self> for Rlwe<F> {
    fn add_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, add_assign)
    }
}

impl<F: NTTField> AddAssign<&Self> for Rlwe<F> {
    fn add_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, add_assign)
    }
}

impl<F: NTTField> SubAssign<Self> for Rlwe<F> {
    fn sub_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, sub_assign)
    }
}

impl<F: NTTField> SubAssign<&Self> for Rlwe<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, sub_assign)
    }
}

impl<F: NTTField> MulAssign<Self> for Rlwe<F> {
    fn mul_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, mul_assign)
    }
}

impl<F: NTTField> MulAssign<&Self> for Rlwe<F> {
    fn mul_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, mul_assign)
    }
}

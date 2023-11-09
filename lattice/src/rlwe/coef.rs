use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::{field::NTTField, polynomial::Polynomial};

use super::RlweModeNTT;

#[derive(Clone)]
pub struct RlweModeCoef<F: NTTField> {
    pub(in crate::rlwe) a: Polynomial<F>,
    pub(in crate::rlwe) b: Polynomial<F>,
}

impl<F: NTTField> RlweModeCoef<F> {
    #[inline]
    pub fn new(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self { a, b }
    }
}

impl<F: NTTField> From<RlweModeNTT<F>> for RlweModeCoef<F> {
    #[inline]
    fn from(rlwe: RlweModeNTT<F>) -> Self {
        let RlweModeNTT { a, b } = rlwe;
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl<F: NTTField> From<&RlweModeNTT<F>> for RlweModeCoef<F> {
    #[inline]
    fn from(rlwe: &RlweModeNTT<F>) -> Self {
        let RlweModeNTT { a, b } = rlwe;
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl<F: NTTField> Add<Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 + a1,
            b: b0 + b1,
        }
    }
}

impl<F: NTTField> Add<&Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 + a1,
            b: b0 + b1,
        }
    }
}

impl<F: NTTField> Sub<Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 - a1,
            b: b0 - b1,
        }
    }
}

impl<F: NTTField> Sub<&Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 - a1,
            b: b0 - b1,
        }
    }
}

impl<F: NTTField> Mul<Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.mul(a1),
            b: b0.mul(b1),
        }
    }
}

impl<F: NTTField> Mul<&Self> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.mul(a1),
            b: b0.mul(b1),
        }
    }
}

impl<F: NTTField> AddAssign<Self> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> AddAssign<&Self> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> SubAssign<Self> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> SubAssign<&Self> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> MulAssign<Self> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> MulAssign<&Self> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

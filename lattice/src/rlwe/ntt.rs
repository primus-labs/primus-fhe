use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use super::RlweModeCoef;

#[derive(Clone)]
pub struct RlweModeNTT<F: NTTField> {
    pub(crate) a: NTTPolynomial<F>,
    pub(crate) b: NTTPolynomial<F>,
}

impl<F: NTTField> RlweModeNTT<F> {
    #[inline]
    pub fn new(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self { a, b }
    }
}

impl<F: NTTField> From<RlweModeCoef<F>> for RlweModeNTT<F> {
    #[inline]
    fn from(rlwe: RlweModeCoef<F>) -> Self {
        let RlweModeCoef { a, b } = rlwe;
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl<F: NTTField> From<&RlweModeCoef<F>> for RlweModeNTT<F> {
    #[inline]
    fn from(rlwe: &RlweModeCoef<F>) -> Self {
        let RlweModeCoef { a, b } = rlwe;
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl<F: NTTField> Add<Self> for RlweModeNTT<F> {
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

impl<F: NTTField> Add<&Self> for RlweModeNTT<F> {
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

impl<F: NTTField> Sub<Self> for RlweModeNTT<F> {
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

impl<F: NTTField> Sub<&Self> for RlweModeNTT<F> {
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

impl<F: NTTField> Mul<Self> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 * a1,
            b: b0 * b1,
        }
    }
}

impl<F: NTTField> Mul<&Self> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0 * a1,
            b: b0 * b1,
        }
    }
}

impl<F: NTTField> AddAssign<Self> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> AddAssign<&Self> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> SubAssign<Self> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> SubAssign<&Self> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> MulAssign<Self> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> MulAssign<&Self> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> Add<NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Add<&NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<&NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> AddAssign<NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> AddAssign<&NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<&NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> Add<Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.add_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Add<&Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.add_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.sub_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<&Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.sub_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> AddAssign<Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        self.b.add_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> AddAssign<&Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.add_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        self.b.sub_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<&Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.sub_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Self {
            a: self.a * &rhs,
            b: self.b * &rhs,
        }
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Self {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.a *= &rhs;
        self.b *= &rhs;
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.a *= rhs;
        self.b *= rhs;
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for RlweModeNTT<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for RlweModeNTT<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

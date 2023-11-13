use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use super::RlweModeNTT;

#[derive(Clone)]
pub struct RlweModeCoef<F: NTTField> {
    pub(crate) a: Polynomial<F>,
    pub(crate) b: Polynomial<F>,
}

impl<F: NTTField> RlweModeCoef<F> {
    /// Creates a new [`RlweModeCoef<F>`].
    #[inline]
    pub fn new(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`RlweModeCoef<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        self.a.as_ref()
    }

    /// Returns a reference to the b of this [`RlweModeCoef<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        self.b.as_ref()
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

impl<F: NTTField> Add<Polynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Add<&Polynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<Polynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<&Polynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> AddAssign<Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> AddAssign<&Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<&Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> Add<NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Add<&NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<&NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> AddAssign<NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.add_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> AddAssign<&NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.add_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.sub_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<&NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.sub_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for RlweModeCoef<F> {
    type Output = RlweModeNTT<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for RlweModeCoef<F> {
    type Output = RlweModeNTT<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = RlweModeNTT<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        RlweModeNTT {
            a: self.a * &rhs,
            b: self.b * &rhs,
        }
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for RlweModeCoef<F> {
    type Output = RlweModeNTT<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        RlweModeNTT {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.a = (self.a() * &rhs).into();
        self.b = (self.b() * &rhs).into();
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for RlweModeCoef<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.a = (self.a() * rhs).into();
        self.b = (self.b() * rhs).into();
    }
}

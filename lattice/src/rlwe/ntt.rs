use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use super::CoefRLWE;

/// A RLWE type whose data is [`NTTPolynomial`]
#[derive(Clone)]
pub struct NttRLWE<F: NTTField> {
    pub(crate) a: NTTPolynomial<F>,
    pub(crate) b: NTTPolynomial<F>,
}

impl<F: NTTField> NttRLWE<F> {
    /// Creates a new [`NttRLWE<F>`].
    #[inline]
    pub fn new(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`NttRLWE<F>`].
    pub fn a(&self) -> &NTTPolynomial<F> {
        self.a.as_ref()
    }

    /// Returns a reference to the b of this [`NttRLWE<F>`].
    pub fn b(&self) -> &NTTPolynomial<F> {
        self.b.as_ref()
    }
}

impl<F: NTTField> From<CoefRLWE<F>> for NttRLWE<F> {
    #[inline]
    fn from(rlwe: CoefRLWE<F>) -> Self {
        let CoefRLWE { a, b } = rlwe;
        Self {
            a: <NTTPolynomial<F>>::from(a),
            b: <NTTPolynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> From<&CoefRLWE<F>> for NttRLWE<F> {
    #[inline]
    fn from(rlwe: &CoefRLWE<F>) -> Self {
        let CoefRLWE { a, b } = rlwe;
        Self {
            a: <NTTPolynomial<F>>::from(a),
            b: <NTTPolynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> Add<Self> for NttRLWE<F> {
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

impl<F: NTTField> Add<&Self> for NttRLWE<F> {
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

impl<F: NTTField> Sub<Self> for NttRLWE<F> {
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

impl<F: NTTField> Sub<&Self> for NttRLWE<F> {
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

impl<F: NTTField> Mul<Self> for NttRLWE<F> {
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

impl<F: NTTField> Mul<&Self> for NttRLWE<F> {
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

impl<F: NTTField> AddAssign<Self> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> AddAssign<&Self> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> SubAssign<Self> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> SubAssign<&Self> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> MulAssign<Self> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> MulAssign<&Self> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> Add<NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Add<&NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<&NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> AddAssign<NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> AddAssign<&NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<&NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> Add<Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.add_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Add<&Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.add_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.sub_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<&Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.sub_assign(NTTPolynomial::from(rhs));
        self
    }
}

impl<F: NTTField> AddAssign<Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        self.b.add_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> AddAssign<&Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.add_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        self.b.sub_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<&Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.sub_assign(NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Self {
            a: self.a * &rhs,
            b: self.b * &rhs,
        }
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Self {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.a *= &rhs;
        self.b *= &rhs;
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.a *= rhs;
        self.b *= rhs;
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for NttRLWE<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for NttRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

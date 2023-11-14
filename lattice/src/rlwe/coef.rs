use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::{
    field::NTTField,
    polynomial::{NTTPolynomial, Polynomial},
};

use super::NttRLWE;

/// A RLWE type whose data is [`Polynomial`]
#[derive(Clone)]
pub struct CoefRLWE<F: NTTField> {
    pub(crate) a: Polynomial<F>,
    pub(crate) b: Polynomial<F>,
}

impl<F: NTTField> CoefRLWE<F> {
    /// Creates a new [`CoefRLWE<F>`].
    #[inline]
    pub fn new(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`CoefRLWE<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        self.a.as_ref()
    }

    /// Returns a reference to the b of this [`CoefRLWE<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        self.b.as_ref()
    }
}

impl<F: NTTField> From<NttRLWE<F>> for CoefRLWE<F> {
    #[inline]
    fn from(rlwe: NttRLWE<F>) -> Self {
        let NttRLWE { a, b } = rlwe;
        Self {
            a: <Polynomial<F>>::from(a),
            b: <Polynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> From<&NttRLWE<F>> for CoefRLWE<F> {
    #[inline]
    fn from(rlwe: &NttRLWE<F>) -> Self {
        let NttRLWE { a, b } = rlwe;
        Self {
            a: <Polynomial<F>>::from(a),
            b: <Polynomial<F>>::from(b),
        }
    }
}

impl<F: NTTField> Add<Self> for CoefRLWE<F> {
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

impl<F: NTTField> Add<&Self> for CoefRLWE<F> {
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

impl<F: NTTField> Sub<Self> for CoefRLWE<F> {
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

impl<F: NTTField> Sub<&Self> for CoefRLWE<F> {
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

impl<F: NTTField> Mul<Self> for CoefRLWE<F> {
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

impl<F: NTTField> Mul<&Self> for CoefRLWE<F> {
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

impl<F: NTTField> AddAssign<Self> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> AddAssign<&Self> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<F: NTTField> SubAssign<Self> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> SubAssign<&Self> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<F: NTTField> MulAssign<Self> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> MulAssign<&Self> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<F: NTTField> Add<Polynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Add<&Polynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.add_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<Polynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Polynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> Sub<&Polynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        self.b.sub_assign(rhs);
        self
    }
}

impl<F: NTTField> AddAssign<Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> AddAssign<&Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.add_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> SubAssign<&Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        self.b.sub_assign(rhs)
    }
}

impl<F: NTTField> Add<NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Add<&NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.add_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> Sub<&NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        self.b.sub_assign(Polynomial::from(rhs));
        self
    }
}

impl<F: NTTField> AddAssign<NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.add_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> AddAssign<&NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.add_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.b.sub_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> SubAssign<&NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.b.sub_assign(Polynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for CoefRLWE<F> {
    type Output = NttRLWE<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for CoefRLWE<F> {
    type Output = NttRLWE<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, NTTPolynomial::from(rhs))
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, NTTPolynomial::from(rhs));
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = NttRLWE<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        NttRLWE {
            a: self.a * &rhs,
            b: self.b * &rhs,
        }
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for CoefRLWE<F> {
    type Output = NttRLWE<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        NttRLWE {
            a: self.a * rhs,
            b: self.b * rhs,
        }
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        self.a = <Polynomial<F>>::from(self.a() * &rhs);
        self.b = <Polynomial<F>>::from(self.b() * &rhs);
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for CoefRLWE<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        self.a = <Polynomial<F>>::from(self.a() * rhs);
        self.b = <Polynomial<F>>::from(self.b() * rhs);
    }
}

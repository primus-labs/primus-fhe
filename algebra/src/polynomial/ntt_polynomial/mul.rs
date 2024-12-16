use std::ops::{Mul, MulAssign};

use crate::{AddOps, MulOps, NTTField, Polynomial};

use super::NTTPolynomial;

impl<F: MulOps> NTTPolynomial<F> {
    /// Multiply `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F) -> Self {
        Self::new(self.iter().map(|&v| v * scalar).collect())
    }

    /// Multiply `self` with the a scalar inplace.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: F) {
        self.iter_mut().for_each(|v| *v *= scalar)
    }

    /// Performs subtraction operation:`self * rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn mul_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&x, &y), z)| {
                *z = x * y;
            })
    }
}

impl<F: MulOps + AddOps> NTTPolynomial<F> {
    /// Multiply `self` with the a scalar inplace.
    #[inline]
    pub fn add_mul_scalar_assign(&mut self, rhs: &Self, scalar: F) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| *r += v * scalar)
    }
}

impl<F: MulOps> MulAssign<Self> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l *= r);
    }
}

impl<F: MulOps> MulAssign<&Self> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, &r)| *l *= r);
    }
}

impl<F: MulOps> Mul<Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: MulOps> Mul<&Self> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: MulOps> Mul<NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, mut rhs: NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self);
        rhs
    }
}

impl<F: MulOps> Mul<&NTTPolynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let data = self.iter().zip(rhs).map(|(&l, &r)| l * r).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

impl<F: NTTField> MulAssign<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        *self *= rhs.into_ntt_polynomial();
    }
}

impl<F: NTTField> MulAssign<&Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        MulAssign::mul_assign(self, rhs.clone());
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        NTTPolynomial::from(rhs) * self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self, rhs.clone())
    }
}

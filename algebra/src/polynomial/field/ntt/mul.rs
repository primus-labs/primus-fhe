use std::ops::{Mul, MulAssign};

use crate::{
    modulus::ShoupFactor,
    reduce::{ReduceAddAssign, ReduceMul, ReduceMulAdd, ReduceMulAssign},
    Field, NttField,
};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Multiply `self` with a scalar.
    #[inline]
    pub fn mul_scalar(mut self, scalar: <F as Field>::ValueT) -> Self {
        self.mul_scalar_assign(scalar);
        self
    }

    /// Multiply `self` with a scalar and assign self.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: <F as Field>::ValueT) {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS.reduce_mul_assign(v, scalar));
    }

    /// Multiply `self` with a scalar and add to self.
    #[inline]
    pub fn add_mul_scalar_assign(&mut self, rhs: &Self, scalar: <F as Field>::ValueT) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| *r = <F as Field>::MODULUS.reduce_mul_add(v, scalar, *r));
    }

    /// Multiply `self` with a scalar.
    #[inline]
    pub fn mul_shoup_scalar(mut self, scalar: ShoupFactor<<F as Field>::ValueT>) -> Self {
        self.mul_shoup_scalar_assign(scalar);
        self
    }

    /// Multiply `self` with a scalar and assign self.
    #[inline]
    pub fn mul_shoup_scalar_assign(&mut self, scalar: ShoupFactor<<F as Field>::ValueT>) {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS_VALUE.reduce_mul_assign(v, scalar));
    }

    /// Multiply `self` with a scalar and add to self.
    #[inline]
    pub fn add_mul_shoup_scalar_assign(
        &mut self,
        rhs: &Self,
        scalar: ShoupFactor<<F as Field>::ValueT>,
    ) {
        self.iter_mut().zip(rhs.iter()).for_each(|(r, &v)| {
            <F as Field>::MODULUS
                .reduce_add_assign(r, <F as Field>::MODULUS_VALUE.reduce_mul(v, scalar))
        })
    }

    /// Performs subtraction operation:`self * rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn mul_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter().zip(rhs).zip(destination).for_each(
            |((&a, &b), z): (
                (&<F as Field>::ValueT, &<F as Field>::ValueT),
                &mut <F as Field>::ValueT,
            )| {
                *z = <F as Field>::MODULUS.reduce_mul(a, b);
            },
        )
    }
}

impl<F: NttField> MulAssign for FieldNttPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, b)| <F as Field>::MODULUS.reduce_mul_assign(a, b));
    }
}

impl<F: NttField> MulAssign<&Self> for FieldNttPolynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| <F as Field>::MODULUS.reduce_mul_assign(a, b));
    }
}

impl<F: NttField> Mul for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Mul<&Self> for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Mul<FieldNttPolynomial<F>> for &FieldNttPolynomial<F> {
    type Output = FieldNttPolynomial<F>;

    #[inline]
    fn mul(self, mut rhs: FieldNttPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self);
        rhs
    }
}

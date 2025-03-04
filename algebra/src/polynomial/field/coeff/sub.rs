use std::ops::{Sub, SubAssign};

use crate::{
    reduce::{ReduceSub, ReduceSubAssign},
    Field,
};

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Performs subtraction operation:`self - rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), c)| *c = F::MODULUS.reduce_sub(a, b));
    }
}

impl<F: Field> SubAssign for FieldPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, b)| F::MODULUS.reduce_sub_assign(a, b));
    }
}

impl<F: Field> SubAssign<&Self> for FieldPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| F::MODULUS.reduce_sub_assign(a, b));
    }
}

impl<F: Field> Sub for FieldPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<&Self> for FieldPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Sub<FieldPolynomial<F>> for &FieldPolynomial<F> {
    type Output = FieldPolynomial<F>;

    #[inline]
    fn sub(self, mut rhs: FieldPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter()
            .zip(rhs.iter_mut())
            .for_each(|(&a, b)| *b = F::MODULUS.reduce_sub(a, *b));
        rhs
    }
}

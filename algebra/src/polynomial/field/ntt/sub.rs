use std::ops::{Sub, SubAssign};

use crate::{
    reduce::{ReduceSub, ReduceSubAssign},
    Field, NttField,
};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Performs subtraction operation:`self - rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), z)| *z = <F as Field>::MODULUS.reduce_sub(a, b));
    }
}

impl<F: NttField> SubAssign for FieldNttPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, b)| <F as Field>::MODULUS.reduce_sub_assign(a, b));
    }
}

impl<F: NttField> SubAssign<&Self> for FieldNttPolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| <F as Field>::MODULUS.reduce_sub_assign(a, b));
    }
}

impl<F: NttField> Sub for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Sub<&Self> for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Sub<FieldNttPolynomial<F>> for &FieldNttPolynomial<F> {
    type Output = FieldNttPolynomial<F>;

    #[inline]
    fn sub(self, mut rhs: FieldNttPolynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        rhs.iter_mut()
            .zip(self)
            .for_each(|(b, &a)| *b = <F as Field>::MODULUS.reduce_sub(a, *b));
        rhs
    }
}

use core::ops::{Add, AddAssign};

use crate::Field;

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), c)| *c = F::add(a, b));
    }
}

impl<F: Field> AddAssign for FieldPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, b)| F::add_assign(a, b));
    }
}

impl<F: Field> AddAssign<&Self> for FieldPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| F::add_assign(a, b));
    }
}

impl<F: Field> Add for FieldPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Add<&Self> for FieldPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: Field> Add<FieldPolynomial<F>> for &FieldPolynomial<F> {
    type Output = FieldPolynomial<F>;

    #[inline]
    fn add(self, mut rhs: FieldPolynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut rhs, self);
        rhs
    }
}

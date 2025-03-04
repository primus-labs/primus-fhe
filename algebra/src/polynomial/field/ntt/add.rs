use core::ops::{Add, AddAssign};

use crate::{
    reduce::{ReduceAdd, ReduceAddAssign},
    Field, NttField,
};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), z)| *z = <F as Field>::MODULUS.reduce_add(a, b));
    }
}

impl<F: NttField> AddAssign for FieldNttPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, b)| <F as Field>::MODULUS.reduce_add_assign(a, b));
    }
}

impl<F: NttField> AddAssign<&Self> for FieldNttPolynomial<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| <F as Field>::MODULUS.reduce_add_assign(a, b));
    }
}

impl<F: NttField> Add for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Add<&Self> for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<F: NttField> Add<FieldNttPolynomial<F>> for &FieldNttPolynomial<F> {
    type Output = FieldNttPolynomial<F>;

    #[inline]
    fn add(self, mut rhs: FieldNttPolynomial<F>) -> Self::Output {
        AddAssign::add_assign(&mut rhs, self);
        rhs
    }
}

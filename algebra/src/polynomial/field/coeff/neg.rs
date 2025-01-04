use core::ops::Neg;

use crate::{
    reduce::{ReduceNeg, ReduceNegAssign},
    Field,
};

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign(&mut self) {
        self.iter_mut()
            .for_each(|v| F::MODULUS.reduce_neg_assign(v));
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_inplace(&self, destination: &mut Self) {
        destination
            .iter_mut()
            .zip(self)
            .for_each(|(output, &input)| *output = F::MODULUS.reduce_neg(input));
    }
}

impl<F: Field> Neg for FieldPolynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.neg_assign();
        self
    }
}

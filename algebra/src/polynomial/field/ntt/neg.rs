use std::ops::Neg;

use crate::{reduce::ReduceNegAssign, Field, NttField};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign(&mut self) {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS.reduce_neg_assign(v));
    }
}

impl<F: NttField> Neg for FieldNttPolynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.neg_assign();
        self
    }
}

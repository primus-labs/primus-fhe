use crate::reduce::{ReduceNeg, ReduceNegAssign};

use super::NttPolynomial;

impl<T: Copy> NttPolynomial<T> {
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg<M>(mut self, modulus: M) -> Self
    where
        M: Copy + ReduceNegAssign<T>,
    {
        self.neg_assign(modulus);
        self
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign<M>(&mut self, modulus: M)
    where
        M: Copy + ReduceNegAssign<T>,
    {
        self.values
            .iter_mut()
            .for_each(|v| modulus.reduce_neg_assign(v));
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_inplace<M>(&self, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        debug_assert_eq!(self.coeff_count(), destination.coeff_count());
        destination
            .iter_mut()
            .zip(self.iter())
            .for_each(|(d, &v)| *d = modulus.reduce_neg(v));
    }
}

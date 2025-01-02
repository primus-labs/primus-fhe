use crate::reduce::{ReduceNeg, ReduceNegAssign};

use super::NumNttPolynomial;

impl<T: Copy> NumNttPolynomial<T> {
    #[inline]
    pub fn neg<M>(mut self, modulus: M) -> Self
    where
        M: Copy + ReduceNegAssign<T>,
    {
        self.neg_assign(modulus);
        self
    }

    #[inline]
    pub fn neg_assign<M>(&mut self, modulus: M)
    where
        M: Copy + ReduceNegAssign<T>,
    {
        self.data
            .iter_mut()
            .for_each(|v| modulus.reduce_neg_assign(v));
    }

    #[inline]
    pub fn neg_inplace<M>(&self, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        destination
            .iter_mut()
            .zip(self.iter())
            .for_each(|(d, &v)| *d = modulus.reduce_neg(v));
    }
}

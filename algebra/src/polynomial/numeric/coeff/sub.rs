use crate::reduce::{ReduceSub, ReduceSubAssign};

use super::Polynomial;

impl<T: Copy> Polynomial<T> {
    /// Performs `self - rhs` according to `modulus`.
    #[inline]
    pub fn sub<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceSubAssign<T>,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs `self -= rhs` according to `modulus`.
    #[inline]
    pub fn sub_assign<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceSubAssign<T>,
    {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| modulus.reduce_sub_assign(a, b));
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn sub_inplace<M>(&self, rhs: &Self, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceSub<T, Output = T>,
    {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert_eq!(self.coeff_count(), destination.coeff_count());
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), c)| *c = modulus.reduce_sub(a, b))
    }
}

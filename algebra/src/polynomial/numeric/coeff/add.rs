use crate::reduce::{ReduceAdd, ReduceAddAssign};

use super::Polynomial;

impl<T: Copy> Polynomial<T> {
    /// Performs `self + rhs` according to `modulus`.
    #[inline]
    pub fn add<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceAddAssign<T>,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs `self += rhs` according to `modulus`.
    #[inline]
    pub fn add_assign<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceAddAssign<T>,
    {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| modulus.reduce_add_assign(a, b));
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace<M>(&self, rhs: &Self, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceAdd<T, Output = T>,
    {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), c)| *c = modulus.reduce_add(a, b));
    }
}

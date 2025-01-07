use crate::{
    integer::UnsignedInteger,
    modulus::ShoupFactor,
    numeric::Numeric,
    reduce::{ReduceMul, ReduceMulAdd, ReduceMulAssign},
};

use super::NttPolynomial;

impl<T: Copy> NttPolynomial<T> {
    /// Multiply `self` with a scalar.
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Multiply `self` with a scalar assign.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar))
    }

    /// Add the multiply result `rhs` with a scalar inplace.
    #[inline]
    pub fn add_mul_scalar_assign<M>(&mut self, rhs: &Self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAdd<T, Output = T>,
    {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| *r = modulus.reduce_mul_add(v, scalar, *r));
    }
}

impl<T: Numeric> NttPolynomial<T> {
    /// Multiply `self` with a shoup scalar.
    #[inline]
    pub fn mul_shoup_scalar(mut self, scalar: ShoupFactor<T>, modulus: T) -> Self {
        self.mul_shoup_scalar_assign(scalar, modulus);
        self
    }

    /// Multiply `self` with a shoup scalar assign.
    #[inline]
    pub fn mul_shoup_scalar_assign(&mut self, scalar: ShoupFactor<T>, modulus: T) {
        self.iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar))
    }

    /// Multiply `self` with a scalar and add to self.
    #[inline]
    pub fn add_mul_shoup_scalar_assign(&mut self, rhs: &Self, scalar: ShoupFactor<T>, modulus: T) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| modulus.reduce_add_assign(r, modulus.reduce_mul(v, scalar)))
    }
}

impl<T: UnsignedInteger> NttPolynomial<T> {
    /// Performs `self * rhs` according to `modulus`.
    #[inline]
    pub fn mul<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.mul_assign(rhs, modulus);
        self
    }

    /// Performs `self *= rhs` according to `modulus`.
    #[inline]
    pub fn mul_assign<M>(&mut self, rhs: &Self, modulus: M)
    where
        M: Copy + ReduceMulAssign<T>,
    {
        self.iter_mut()
            .zip(rhs)
            .for_each(|(a, &b)| modulus.reduce_mul_assign(a, b));
    }

    /// Performs `destination = self * rhs` according to `modulus`.
    #[inline]
    pub fn mul_inplace<M>(&self, rhs: &Self, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceMul<T, Output = T>,
    {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&a, &b), c)| *c = modulus.reduce_mul(a, b));
    }
}

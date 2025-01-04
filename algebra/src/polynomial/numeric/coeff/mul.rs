use crate::{
    integer::UnsignedInteger,
    modulus::ShoupFactor,
    numeric::Numeric,
    reduce::{ReduceAddAssign, ReduceMul, ReduceMulAdd, ReduceMulAssign, ReduceSubAssign},
};

use super::NumPolynomial;

impl<T: Copy> NumPolynomial<T> {
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

impl<T: UnsignedInteger> NumPolynomial<T> {
    /// A naive multiplication over polynomial.
    pub fn naive_mul_inplace<M>(&self, rhs: impl AsRef<[T]>, modulus: M, destination: &mut Self)
    where
        M: Copy + ReduceAddAssign<T> + ReduceSubAssign<T> + ReduceMul<T, Output = T>,
    {
        let poly1: &[T] = self.as_ref();
        let poly2: &[T] = rhs.as_ref();

        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, poly2.len());
        debug_assert_eq!(coeff_count, destination.coeff_count());

        for i in 0..coeff_count {
            for j in 0..=i {
                modulus.reduce_add_assign(
                    &mut destination[i],
                    modulus.reduce_mul(poly1[j], poly2[i - j]),
                );
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                modulus.reduce_sub_assign(
                    &mut destination[k],
                    modulus.reduce_mul(poly1[j], poly2[i - j]),
                );
            }
        }
    }
}

impl<T: Numeric> NumPolynomial<T> {
    /// Multiply `self` with a scalar.
    #[inline]
    pub fn mul_shoup_scalar(mut self, scalar: ShoupFactor<T>, modulus: T) -> Self {
        self.mul_shoup_scalar_assign(scalar, modulus);
        self
    }

    /// Multiply `self` with a scalar inplace.
    #[inline]
    pub fn mul_shoup_scalar_assign(&mut self, scalar: ShoupFactor<T>, modulus: T) {
        self.iter_mut()
            .for_each(|v| modulus.reduce_mul_assign(v, scalar))
    }
}

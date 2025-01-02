use crate::{
    modulus::ShoupFactor,
    reduce::{ReduceAddAssign, ReduceMul, ReduceMulAdd, ReduceMulAssign},
    Field,
};

use super::FieldPolynomial;

impl<F: Field> FieldPolynomial<F> {
    /// Multiply `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(mut self, scalar: <F as Field>::ValueT) -> Self {
        self.mul_scalar_assign(scalar);
        self
    }

    /// Multiply `self` with the a scalar and assign self.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: <F as Field>::ValueT) {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS.reduce_mul_assign(v, scalar))
    }

    /// Multiply `self` with the a scalar and add to self.
    #[inline]
    pub fn add_mul_scalar_assign(&mut self, rhs: &Self, scalar: <F as Field>::ValueT) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| *r = <F as Field>::MODULUS.reduce_mul_add(v, scalar, *r))
    }

    /// Multiply `self` with the a shoup scalar.
    #[inline]
    pub fn mul_shoup_scalar(mut self, scalar: ShoupFactor<<F as Field>::ValueT>) -> Self {
        self.mul_shoup_scalar_assign(scalar);
        self
    }

    /// Multiply `self` with the a shoup scalar and assign self.
    #[inline]
    pub fn mul_shoup_scalar_assign(&mut self, scalar: ShoupFactor<<F as Field>::ValueT>) {
        self.iter_mut()
            .for_each(|v| <F as Field>::MODULUS_VALUE.reduce_mul_assign(v, scalar));
    }

    /// Multiply `self` with the a shoup scalar and add to self.
    #[inline]
    pub fn add_mul_shoup_scalar_assign(
        &mut self,
        rhs: &Self,
        scalar: ShoupFactor<<F as Field>::ValueT>,
    ) {
        self.iter_mut().zip(rhs).for_each(|(r, &v)| {
            <F as Field>::MODULUS
                .reduce_add_assign(r, <F as Field>::MODULUS_VALUE.reduce_mul(v, scalar))
        });
    }
}

use primus_data::{Data, DataMut};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{ReduceMulAddSlice, ReduceMulSlice};

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self * scalar` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Performs `self * factor` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn mul_factor<F>(mut self, factor: F, modulus: T) -> Self
    where
        F: FactorSliceOps<T>,
    {
        self.mul_factor_assign(factor, modulus);
        self
    }

    /// Performs `self * rhs` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn mul<M, A>(mut self, rhs: &NttPolynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
        A: Data<Elem = T>,
    {
        self.mul_assign(rhs, modulus);
        self
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.as_mut_slice(), scalar);
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.as_mut_slice(), rhs.as_slice(), scalar);
    }

    /// Performs `self *= factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        factor.factor_mul_slice_assign(self.as_mut_slice(), modulus)
    }

    /// Performs `self += factor * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &NttPolynomial<A>, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: Data<Elem = T>,
    {
        factor.add_factor_mul_slice_assign(self.as_mut_slice(), rhs.as_slice(), modulus);
    }

    /// Performs `self *= rhs` according to `modulus`.
    #[inline]
    pub fn mul_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_mul_slice_assign(self.as_mut_slice(), rhs.as_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `result = self * rhs` according to `modulus`.
    #[inline]
    pub fn mul_to<M, A, B>(&self, rhs: &NttPolynomial<A>, output: &mut NttPolynomial<B>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_mul_slice_to(self.as_slice(), rhs.as_slice(), output.as_mut_slice());
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.reduce_mul_scalar_slice_to(self.as_slice(), scalar, output.as_mut_slice());
    }

    /// Performs `result = self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut NttPolynomial<A>, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: DataMut<Elem = T>,
    {
        factor.factor_mul_slice_to(self.as_slice(), output.as_mut_slice(), modulus);
    }
}

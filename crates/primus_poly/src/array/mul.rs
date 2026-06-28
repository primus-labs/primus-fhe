use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{ReduceAdd, ReduceMul, ReduceMulAddSlice, ReduceMulSlice, ReduceSub};

use super::ArrayBase;

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &ArrayBase<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        factor.factor_mul_slice_assign(self.as_mut(), modulus)
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &ArrayBase<A>, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + Data,
    {
        factor.add_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
    }

    /// Performs `self * rhs` according to `modulus`.
    #[inline]
    pub fn mul_element_wise<M, A>(mut self, rhs: &ArrayBase<A>, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.mul_element_wise_assign(rhs, modulus);
        self
    }

    /// Performs `self *= rhs` according to `modulus`.
    #[inline]
    pub fn mul_element_wise_assign<M, A>(&mut self, rhs: &ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_mul_slice_assign(self.as_mut(), rhs.as_ref());
    }

    /// Inverse butterfly: `(self[i], result[i]) = (self[i] + rhs[i], (self[i] - rhs[i]) * w[i])`
    #[inline]
    pub fn butterfly_mul_element_wise_to<M, A, B, C>(
        &mut self,
        rhs: &ArrayBase<A>,
        w: &ArrayBase<B>,
        output: &mut ArrayBase<C>,
        modulus: M,
    ) where
        M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T> + ReduceMul<T, Output = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        debug_assert_eq!(self.len(), rhs.len());
        debug_assert_eq!(self.len(), w.len());
        debug_assert_eq!(self.len(), output.len());
        izip!(self, rhs, w, output).for_each(|(a, &s, &w, b)| {
            let a_orig = *a;
            *a = modulus.reduce_add(a_orig, s);
            *b = modulus.reduce_mul(modulus.reduce_sub(a_orig, s), w);
        });
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs element wise modular multiplication operation `result = self * rhs` according to `modulus`.
    #[inline]
    pub fn mul_element_wise_to<M, A, B>(
        &self,
        rhs: &ArrayBase<A>,
        output: &mut ArrayBase<B>,
        modulus: M,
    ) where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_mul_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
    }

    /// Performs `result = self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut ArrayBase<A>, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        factor.factor_mul_slice_to(self.as_ref(), output.as_mut(), modulus);
    }
}

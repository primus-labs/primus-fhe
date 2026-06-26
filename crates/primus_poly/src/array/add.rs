use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::{ReduceAddSlice, ReduceMulAddSlice};

use super::ArrayBase;

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self + rhs` according to `modulus`.
    #[inline]
    pub fn add_element_wise<M, A>(mut self, rhs: &ArrayBase<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.add_element_wise_assign(rhs, modulus);
        self
    }

    /// Performs `self += rhs` according to `modulus`.
    #[inline]
    pub fn add_element_wise_assign<M, A>(&mut self, rhs: &ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_slice_assign(self.as_mut_slice(), rhs.as_slice());
    }

    /// Performs `self += b * c` according to `modulus`.
    #[inline]
    pub fn add_mul_element_wise_assign<M, A, B>(
        &mut self,
        b: &ArrayBase<A>,
        c: &ArrayBase<B>,
        modulus: M,
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_mul_slice_assign(self.as_mut_slice(), b.as_slice(), c.as_slice());
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self + rhs` according to `modulus`.
    #[inline]
    pub fn add_element_wise_to<M, A, B>(
        &self,
        rhs: &ArrayBase<A>,
        output: &mut ArrayBase<B>,
        modulus: M,
    ) where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_add_slice_to(self.as_slice(), rhs.as_slice(), output.as_mut_slice());
    }
}

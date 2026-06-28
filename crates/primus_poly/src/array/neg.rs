use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceNegSlice;

use super::ArrayBase;

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg<M>(mut self, modulus: M) -> Self
    where
        M: Copy + ReduceNegSlice<T>,
    {
        self.neg_assign(modulus);
        self
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign<M>(&mut self, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
    {
        modulus.reduce_neg_slice_assign(self.as_mut());
    }
}

impl<S, T> ArrayBase<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<M, A>(&self, output: &mut ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_neg_slice_to(self.as_ref(), output.as_mut());
    }
}

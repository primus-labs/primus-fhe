use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceNegSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
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
        modulus.reduce_neg_slice_assign(self.as_mut_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<M, A>(&self, output: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_neg_slice_to(self.as_slice(), output.as_mut_slice());
    }
}

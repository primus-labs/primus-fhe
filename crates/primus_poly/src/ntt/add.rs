use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceAddSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self + rhs` according to `modulus`.
    #[inline]
    pub fn add<M, A>(mut self, rhs: &NttPolynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs `self += rhs` according to `modulus`.
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_slice_assign(self.as_mut_slice(), rhs.as_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self + rhs` according to `modulus`.
    #[inline]
    pub fn add_to<M, A, B>(&self, rhs: &NttPolynomial<A>, output: &mut NttPolynomial<B>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_add_slice_to(self.as_slice(), rhs.as_slice(), output.as_mut_slice());
    }
}

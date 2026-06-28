use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceSubSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self - rhs` according to `modulus`.
    #[inline]
    pub fn sub<M, A>(mut self, rhs: &NttPolynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs `self -= rhs` according to `modulus`.
    #[inline]
    pub fn sub_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_sub_slice_assign(self.as_mut(), rhs.as_ref());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `rhs = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_rev_assign<M, A>(&self, rhs: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_sub_slice_rev_assign(self.as_ref(), rhs.as_mut());
    }

    /// Performs `result = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_to<M, A, B>(&self, rhs: &NttPolynomial<A>, output: &mut NttPolynomial<B>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }
}

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::ReduceSubSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self - rhs` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn sub<M, A>(mut self, rhs: &NttPolynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs `self -= rhs` according to `modulus`.
    #[inline]
    pub fn sub_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_sub_slice_assign(self.as_mut(), rhs.as_ref());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `rhs = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_rev_assign<M, A>(&self, rhs: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_rev_assign(self.as_ref(), rhs.as_mut());
    }

    /// Performs `result = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_to<M, A, B>(&self, rhs: &NttPolynomial<A>, output: &mut NttPolynomial<B>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }
}

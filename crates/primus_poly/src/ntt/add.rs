use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::ReduceAddSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self + rhs` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn add<M, A>(mut self, rhs: &NttPolynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs `self += rhs` according to `modulus`.
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_slice_assign(self.as_mut_slice(), rhs.as_slice());
    }
}

impl<S, T> NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `result = self + rhs` according to `modulus`.
    #[inline]
    pub fn add_to<M, A, B>(&self, rhs: &NttPolynomial<A>, output: &mut NttPolynomial<B>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_add_slice_to(self.as_slice(), rhs.as_slice(), output.as_mut_slice());
    }
}

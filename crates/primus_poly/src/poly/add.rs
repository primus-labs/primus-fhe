use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceAddSlice;

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self + rhs` according to `modulus`.
    #[inline]
    pub fn add<M, A>(mut self, rhs: &Polynomial<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs `self += rhs` according to `modulus`.
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &Polynomial<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_slice_assign(self.as_mut(), rhs.as_ref());
    }
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self + rhs` according to `modulus`.
    #[inline]
    pub fn add_to<M, A, B>(&self, rhs: &Polynomial<A>, output: &mut Polynomial<B>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_add_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }
}

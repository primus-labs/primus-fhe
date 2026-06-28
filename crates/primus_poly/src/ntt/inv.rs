use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceInvSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs the point-wise inverse in the NTT domain.
    ///
    /// # Panics
    ///
    /// Panics if `scratch.len() < self.poly_length()` or any value is zero.
    #[inline]
    pub fn inv<M>(mut self, modulus: M, scratch: &mut [T]) -> Self
    where
        M: Copy + ReduceInvSlice<T>,
    {
        self.inv_assign(modulus, scratch);
        self
    }

    /// Performs the point-wise inverse in the NTT domain in place.
    ///
    /// # Panics
    ///
    /// Panics if `scratch.len() < self.poly_length()` or any value is zero.
    #[inline]
    pub fn inv_assign<M>(&mut self, modulus: M, scratch: &mut [T])
    where
        M: Copy + ReduceInvSlice<T>,
    {
        modulus.reduce_inv_slice_assign(self.as_mut_slice(), scratch);
    }
}

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the point-wise inverse in the NTT domain.
    ///
    /// # Panics
    ///
    /// Panics if `output.poly_length() < self.poly_length()` or any value is zero.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceInvSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_inv_slice_to(self.as_slice(), output.as_mut_slice());
    }
}

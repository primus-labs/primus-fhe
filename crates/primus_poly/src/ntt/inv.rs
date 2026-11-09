use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::{ReduceError, ReduceInvSlice, TryReduceInvSlice};

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs the point-wise inverse in the NTT domain.
    ///
    /// # Correctness
    ///
    /// - `output.len()` equals `self.len()`
    /// - Every input value is less than `modulus`
    ///
    /// # Panics
    ///
    /// Panics if any value has no inverse modulo `modulus`.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceInvSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.reduce_inv_slice_to(self.as_slice(), output.as_mut_slice());
    }

    /// Attempts to write the point-wise inverse in the NTT domain to `output`.
    ///
    /// # Correctness
    ///
    /// - `output.len()` equals `self.len()`
    /// - Every input value is less than `modulus`
    ///
    /// # Errors
    ///
    /// Returns a [`ReduceError`] if any point value has no inverse modulo
    /// `modulus`. `output` may be modified when an error is returned.
    #[inline]
    pub fn try_inv_to<M, A>(
        &self,
        output: &mut NttPolynomial<A>,
        modulus: M,
    ) -> Result<(), ReduceError<T>>
    where
        M: Copy + TryReduceInvSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.try_reduce_inv_slice_to(self.as_slice(), output.as_mut_slice())
    }
}

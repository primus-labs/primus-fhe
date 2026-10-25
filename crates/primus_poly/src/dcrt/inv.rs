use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::{ReduceError, ReduceInvSlice, TryReduceInvSlice};

use super::DcrtPolynomial;

impl<S, T> DcrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Writes the point-wise inverse of each modulus component to `output`.
    ///
    /// # Correctness
    ///
    /// - `poly_length` is nonzero
    /// - Input and output storage have the same length and are both divisible
    ///   by `poly_length`
    /// - `moduli.len()` equals the number of modulus components
    /// - Every input value is less than its component modulus
    ///
    /// # Panics
    ///
    /// Panics if any value has no inverse modulo its component modulus.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceInvSlice<T>,
        A: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        debug_assert_eq!(self.len(), output.len());
        debug_assert_eq!(self.len(), moduli.len() * poly_length);

        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(poly, out, &modulus)| modulus.reduce_inv_slice_to(poly, out));
    }

    /// Attempts to write the point-wise inverse of each modulus component to `output`.
    ///
    /// # Correctness
    ///
    /// - `poly_length` is nonzero
    /// - Input and output storage have the same length and are both divisible
    ///   by `poly_length`
    /// - `moduli.len()` equals the number of modulus components
    /// - Every input value is less than its component modulus
    ///
    /// # Errors
    ///
    /// Returns a [`ReduceError`] if any point value has no inverse modulo its
    /// component modulus. `output` may be partially modified when an error is
    /// returned.
    #[inline]
    pub fn try_inv_to<M, A>(
        &self,
        output: &mut DcrtPolynomial<A>,
        poly_length: usize,
        moduli: &[M],
    ) -> Result<(), ReduceError<T>>
    where
        M: Copy + TryReduceInvSlice<T>,
        A: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        debug_assert_eq!(self.len(), output.len());
        debug_assert_eq!(self.len(), moduli.len() * poly_length);

        for (poly, out, &modulus) in izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        ) {
            modulus.try_reduce_inv_slice_to(poly, out)?;
        }

        Ok(())
    }
}

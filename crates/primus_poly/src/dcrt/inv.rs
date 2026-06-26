use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceInvSlice;

use super::DcrtPolynomial;

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs the point-wise inverse for each modulus component.
    ///
    /// # Panics
    ///
    /// Panics if `scratch.len() < poly_length` or any value is zero.
    #[inline]
    pub fn inv<M>(mut self, poly_length: usize, moduli: &[M], scratch: &mut [T]) -> Self
    where
        M: Copy + ReduceInvSlice<T>,
    {
        self.inv_assign(poly_length, moduli, scratch);
        self
    }

    /// Performs the point-wise inverse for each modulus component in place.
    ///
    /// # Panics
    ///
    /// Panics if `scratch.len() < poly_length` or any value is zero.
    #[inline]
    pub fn inv_assign<M>(&mut self, poly_length: usize, moduli: &[M], scratch: &mut [T])
    where
        M: Copy + ReduceInvSlice<T>,
    {
        debug_assert!(scratch.len() >= poly_length);

        izip!(self.iter_each_modulus_mut(poly_length), moduli)
            .for_each(|(poly, &modulus)| modulus.reduce_inv_slice_assign(poly, scratch));
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the point-wise inverse for each modulus component in place.
    ///
    /// # Panics
    ///
    /// Panics if `self.dcrt_poly_length() ≠ output.dcrt_poly_length()` or any value is zero.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceInvSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        debug_assert_eq!(self.dcrt_poly_length(), output.dcrt_poly_length());

        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(poly, out, &modulus)| modulus.reduce_inv_slice_to(poly, out));
    }
}

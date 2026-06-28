use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceNegSlice;

use super::DcrtPolynomial;

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg<M>(mut self, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceNegSlice<T>,
    {
        self.neg_assign(poly_length, moduli);
        self
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign<M>(&mut self, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceNegSlice<T>,
    {
        self.iter_each_modulus_mut(poly_length)
            .zip(moduli)
            .for_each(|(poly, &modulus)| modulus.reduce_neg_slice_assign(poly));
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<M, A>(&self, output: &mut DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceNegSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(input, output, &modulus)| modulus.reduce_neg_slice_to(input, output));
    }
}

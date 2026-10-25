use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::ReduceNegSlice;

use super::CrtPolynomial;

impl<S, T> CrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[must_use]
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

impl<S, T> CrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<M, A>(&self, output: &mut CrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceNegSlice<T>,
        A: DataMut<Elem = T>,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(xs, ys, &modulus)| modulus.reduce_neg_slice_to(xs, ys));
    }
}

use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::ReduceAddSlice;

use super::CrtPolynomial;

impl<S, T> CrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self + rhs` according to `moduli`.
    #[must_use]
    #[inline]
    pub fn add<M, A>(mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        self.add_assign(rhs, poly_length, moduli);
        self
    }

    /// Performs `self += rhs` according to `moduli`.
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            moduli
        )
        .for_each(|(lhs, rhs, &modulus)| modulus.reduce_add_slice_assign(lhs, rhs));
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `result = self + rhs` according to `moduli`.
    #[inline]
    pub fn add_to<M, A, B>(
        &self,
        rhs: &CrtPolynomial<A>,
        output: &mut CrtPolynomial<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(lhs, rhs, output, &modulus)| {
            modulus.reduce_add_slice_to(lhs, rhs, output);
        });
    }
}

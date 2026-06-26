use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceAddSlice;

use crate::ArrayBase;

use super::CrtPolynomial;

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self + rhs` according to `moduli`.
    #[inline]
    pub fn add<M, A>(mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.add_assign(rhs, poly_length, moduli);
        self
    }

    /// Performs `self += rhs` according to `moduli`.
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            moduli
        )
        .for_each(|(xs, ys, &modulus)| {
            ArrayBase(xs).add_element_wise_assign(&ArrayBase(ys), modulus);
        });
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
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
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(xs, ys, zs, &modulus)| {
            ArrayBase(xs).add_element_wise_to(&ArrayBase(ys), &mut ArrayBase(zs), modulus);
        });
    }
}

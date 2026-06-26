use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceSubSlice;

use super::CrtPolynomial;

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self - rhs` according to `moduli`.
    #[inline]
    pub fn sub<M, A>(mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.sub_assign(rhs, poly_length, moduli);
        self
    }

    /// Performs `self -= rhs` according to `moduli`.
    #[inline]
    pub fn sub_assign<M, A>(&mut self, rhs: &CrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            moduli
        )
        .for_each(|(a, b, &modulus)| modulus.reduce_sub_slice_assign(a, b));
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self - rhs` according to `moduli`.
    #[inline]
    pub fn sub_to<M, A, B>(
        &self,
        rhs: &CrtPolynomial<A>,
        output: &mut CrtPolynomial<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, b, output, &modulus)| modulus.reduce_sub_slice_to(a, b, output));
    }

    /// Performs `rhs = self - rhs` according to `moduli`.
    #[inline]
    pub fn sub_rev_assign<M, A>(&self, rhs: &mut CrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceSubSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, b, &modulus)| modulus.reduce_sub_slice_rev_assign(a, b));
    }
}

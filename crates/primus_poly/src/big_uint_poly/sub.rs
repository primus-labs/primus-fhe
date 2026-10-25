use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::{BigUint, FheUint};

use super::BigUintPolynomial;

impl<S, T> BigUintPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self - rhs` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn sub<A, B>(mut self, rhs: &BigUintPolynomial<A>, modulus: &BigUint<B>) -> Self
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs `self -= rhs` according to `modulus`.
    #[inline]
    pub fn sub_assign<A, B>(&mut self, rhs: &BigUintPolynomial<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), rhs.len());
        let value_len = modulus.len();
        self.iter_mut(value_len)
            .zip(rhs.iter(value_len))
            .for_each(|(mut a, b)| {
                a.sub_modulo_assign(&b, modulus);
            });
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `result = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_to<A, B, C>(
        &self,
        rhs: &BigUintPolynomial<A>,
        output: &mut BigUintPolynomial<B>,
        modulus: &BigUint<C>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), rhs.len());
        debug_assert_eq!(self.len(), output.len());
        let value_len = modulus.len();
        izip!(
            self.iter(value_len),
            rhs.iter(value_len),
            output.iter_mut(value_len)
        )
        .for_each(|(a, b, mut c)| {
            a.sub_modulo_to(&b, &mut c, modulus);
        });
    }

    /// Performs `rhs = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_rev_assign<A, C>(&self, rhs: &mut BigUintPolynomial<A>, modulus: &BigUint<C>)
    where
        A: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), rhs.len());
        let value_len = modulus.len();
        rhs.iter_mut(value_len)
            .zip(self.iter(value_len))
            .for_each(|(mut b, a)| {
                b.sub_modulo_rev_assign(&a, modulus);
            });
    }
}

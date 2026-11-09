use primus_data::{Data, DataMut};
use primus_integer::{BigUint, FheUint};

use super::BigUintPolynomial;

impl<S, T> BigUintPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[must_use]
    #[inline]
    pub fn neg<A>(mut self, modulus: &BigUint<A>) -> Self
    where
        A: Data<Elem = T>,
    {
        self.neg_assign(modulus);
        self
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign<A>(&mut self, modulus: &BigUint<A>)
    where
        A: Data<Elem = T>,
    {
        let value_len = modulus.len();
        self.iter_mut(value_len)
            .for_each(|mut v| v.neg_modulo_assign(modulus));
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<A, B>(&self, output: &mut BigUintPolynomial<A>, modulus: &BigUint<B>)
    where
        A: DataMut<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), output.len());
        let value_len = modulus.len();
        output
            .iter_mut(value_len)
            .zip(self.iter(value_len))
            .for_each(|(mut d, v)| v.neg_modulo_to(&mut d, modulus));
    }
}

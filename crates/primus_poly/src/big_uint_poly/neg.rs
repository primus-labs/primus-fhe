use primus_data::{Data, DataMut, RawData};
use primus_integer::{BigUint, FheUint};

use super::BigUintPolynomial;

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg<A>(mut self, modulus: &BigUint<A>) -> Self
    where
        A: RawData<Elem = T> + Data,
    {
        self.neg_assign(modulus);
        self
    }

    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign<A>(&mut self, modulus: &BigUint<A>)
    where
        A: RawData<Elem = T> + Data,
    {
        let value_len = modulus.len();
        self.iter_mut(value_len)
            .for_each(|mut v| v.neg_modulo_assign(modulus));
    }
}

impl<S, T> BigUintPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_to<A, B>(&self, output: &mut BigUintPolynomial<A>, modulus: &BigUint<B>)
    where
        A: RawData<Elem = T> + DataMut,
        B: RawData<Elem = T> + Data,
    {
        debug_assert_eq!(self.len(), output.len());
        let value_len = modulus.len();
        output
            .iter_mut(value_len)
            .zip(self.iter(value_len))
            .for_each(|(mut d, v)| v.neg_modulo_to(&mut d, modulus));
    }
}

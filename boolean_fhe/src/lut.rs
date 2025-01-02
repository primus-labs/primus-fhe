use std::iter::once;

use algebra::{polynomial::FieldPolynomial, reduce::ReduceNeg, Field};
use itertools::Itertools;

pub trait LookUpTable<Q: Field> {
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q>;
    fn half_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q>;
}

impl<Q: Field, const N: usize> LookUpTable<Q> for [<Q as Field>::ValueT; N] {
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> log_t;

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(self.iter().interleave(self[1..].iter()))
            .for_each(
                |(chunk, &value): (&mut [<Q as Field>::ValueT], &<Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }

    fn half_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> (log_t + 1);

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(
                self.iter()
                    .interleave(self[1..].iter())
                    .chain(once(&Q::MODULUS.reduce_neg(self[0]))),
            )
            .for_each(
                |(chunk, &value): (&mut [<Q as Field>::ValueT], &<Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }
}

impl<Q: Field> LookUpTable<Q> for &[<Q as Field>::ValueT] {
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> log_t;

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(self.iter().interleave(self[1..].iter()))
            .for_each(
                |(chunk, &value): (&mut [<Q as Field>::ValueT], &<Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }

    fn half_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> (log_t + 1);

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(
                self.iter()
                    .interleave(self[1..].iter())
                    .chain(once(&Q::MODULUS.reduce_neg(self[0]))),
            )
            .for_each(
                |(chunk, &value): (&mut [<Q as Field>::ValueT], &<Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }
}

impl<Q: Field, LutFn> LookUpTable<Q> for LutFn
where
    LutFn: Fn(usize) -> <Q as Field>::ValueT,
{
    fn negacyclic_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> log_t;
        let t = 1 << log_t;

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip((0..t).map(self).interleave((1..t).map(self)))
            .for_each(
                |(chunk, value): (&mut [<Q as Field>::ValueT], <Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }

    fn half_lut(&self, coeff_count: usize, log_t: u32) -> FieldPolynomial<Q> {
        let mut lut = <FieldPolynomial<Q>>::zero(coeff_count);
        let half_delta = coeff_count >> (log_t + 1);
        let t = 1 << log_t;

        lut.as_mut_slice()
            .chunks_mut(half_delta)
            .zip(
                (0..t)
                    .map(self)
                    .interleave((1..t).map(self))
                    .chain(once(Q::MODULUS.reduce_neg(self(0)))),
            )
            .for_each(
                |(chunk, value): (&mut [<Q as Field>::ValueT], <Q as Field>::ValueT)| {
                    chunk.fill(value);
                },
            );
        lut
    }
}

use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{ReduceMulAddSlice, ReduceMulSlice, ReduceNegSlice};

use super::CrtPolynomial;

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self * scalar` according to `moduli`.
    #[inline]
    pub fn mul_scalar<M>(mut self, scalars: &[T], poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalars, poly_length, moduli);
        self
    }

    /// Performs `self *= scalar` according to `moduli`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalars: &[T], poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceMulSlice<T>,
    {
        izip!(self.iter_each_modulus_mut(poly_length), scalars, moduli).for_each(
            |(poly, &scalar, &modulus)| modulus.reduce_mul_scalar_slice_assign(poly, scalar),
        )
    }

    /// Performs `self * scalar` according to `moduli`.
    #[inline]
    pub fn mul_factor<F>(mut self, factors: &[F], poly_length: usize, moduli: &[T]) -> Self
    where
        F: Copy + FactorSliceOps<T>,
    {
        self.mul_factor_assign(factors, poly_length, moduli);
        self
    }

    /// Performs `self *= scalar` according to `moduli`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factors: &[F], poly_length: usize, moduli: &[T])
    where
        F: Copy + FactorSliceOps<T>,
    {
        izip!(self.iter_each_modulus_mut(poly_length), factors, moduli)
            .for_each(|(poly, &factor, &modulus)| factor.factor_mul_slice_assign(poly, modulus))
    }

    /// Performs `self += scalar * rhs` according to `moduli`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(
        &mut self,
        rhs: &CrtPolynomial<A>,
        scalars: &[T],
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            scalars,
            moduli
        )
        .for_each(|(acc, r, &scalar, &modulus)| {
            modulus.reduce_add_mul_scalar_slice_assign(acc, r, scalar);
        });
    }

    /// Performs `self += scalar * rhs` according to `moduli`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(
        &mut self,
        rhs: &CrtPolynomial<A>,
        factors: &[F],
        poly_length: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: RawData<Elem = T> + Data,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            factors,
            moduli
        )
        .for_each(|(acc, r, &factor, &modulus)| {
            factor.add_factor_mul_slice_assign(acc, r, modulus);
        });
    }

    /// Multiplies `self` by the monomial `X^r`, in place, for each modulus component.
    pub fn mul_monomial_assign<M>(&mut self, r: usize, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceNegSlice<T>,
    {
        if r < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[0..r]);
            };

            self.iter_each_modulus_mut(poly_length)
                .zip(moduli)
                .for_each(|(poly, &modulus)| rotate(poly, modulus));
        } else {
            debug_assert!(r < poly_length * 2);
            let r = r - poly_length;

            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[r..]);
            };

            self.iter_each_modulus_mut(poly_length)
                .zip(moduli)
                .for_each(|(poly, &modulus)| rotate(poly, modulus));
        }
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self * scalar` according to `moduli`.
    #[inline]
    pub fn mul_scalar_to<M, A>(
        &self,
        scalars: &[T],
        output: &mut CrtPolynomial<A>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            scalars,
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, &scalar, output, &modulus)| {
            modulus.reduce_mul_scalar_slice_to(a, scalar, output);
        })
    }

    /// Performs `result = self * scalar` according to `moduli`.
    #[inline]
    pub fn mul_factor_to<F, A>(
        &self,
        factors: &[F],
        output: &mut CrtPolynomial<A>,
        poly_length: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            factors,
            moduli
        )
        .for_each(|(in_poly, out_poly, &factor, &modulus)| {
            factor.factor_mul_slice_to(in_poly, out_poly, modulus);
        })
    }
}

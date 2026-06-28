use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_factor::{Factor, FactorMul, FactorSliceOps};
use primus_integer::FheUint;
use primus_modulus::common::compact;
use primus_reduce::{ReduceMulAddSlice, ReduceMulSlice};

#[cfg(feature = "simd")]
use primus_factor::SimdFactorMul;
#[cfg(feature = "simd")]
use primus_integer::SimdArray;

use super::DcrtPolynomial;

fn slice_butterfly<T, F>(a: &mut [T], s: &[T], w: &[F], b: &mut [T], modulus: T)
where
    T: FheUint,
    F: Copy + FactorMul<T>,
{
    debug_assert_eq!(a.len(), s.len());
    debug_assert_eq!(a.len(), w.len());
    debug_assert_eq!(a.len(), b.len());

    izip!(a, s, w, b).for_each(|(a, &s, &w, b)| {
        let a_orig = *a;
        compact::reduce_add_assign(modulus, a, s);
        let diff = compact::reduce_sub(modulus, a_orig, s);
        *b = w.factor_mul_modulo(diff, modulus);
    });
}

#[cfg(feature = "simd")]
#[allow(clippy::chunks_exact_to_as_chunks)]
fn simd_butterfly<T, F>(a: &mut [T], s: &[T], w: &[F], b: &mut [T], modulus: T)
where
    T: FheUint,
    F: SimdFactorMul<T>,
{
    debug_assert_eq!(a.len(), s.len());
    debug_assert_eq!(a.len(), w.len());
    debug_assert_eq!(a.len(), b.len());

    let m = T::SimdT::splat(modulus);

    let (a_chunks, a_rem) = T::simd_as_chunks_mut(a);
    let (s_chunks, s_rem) = T::simd_as_chunks(s);
    let (out_chunks, out_rem) = T::simd_as_chunks_mut(b);

    let simd_len = a_chunks.len() * T::LANE_COUNT;
    let (w_body, w_rem) = w.split_at(simd_len);

    for (((a, &s), w), b) in a_chunks
        .iter_mut()
        .zip(s_chunks)
        .zip(w_body.chunks_exact(T::LANE_COUNT))
        .zip(out_chunks)
    {
        let av = T::SimdT::from_array(*a);
        let sv = T::SimdT::from_array(s);
        let wf = F::simd_from_factor_slice(w);

        let diff = compact::simd::reduce_sub::<T>(m, av, sv);

        *a = compact::simd::reduce_add::<T>(m, av, sv).to_array();
        *b = wf.factor_mul_modulo(diff, m).to_array();
    }

    slice_butterfly(a_rem, s_rem, w_rem, out_rem, modulus);
}

impl<S, T> DcrtPolynomial<S>
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

    /// Performs `self += scalar * rhs` according to `moduli`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
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
        .for_each(|(acc, a, &scalar, &modulus)| {
            modulus.reduce_add_mul_scalar_slice_assign(acc, a, scalar)
        });
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
    pub fn add_mul_factor_assign<F, A>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
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
        .for_each(|(poly, rhs, &factor, &modulus)| {
            factor.add_factor_mul_slice_assign(poly, rhs, modulus)
        })
    }

    /// Performs `self * rhs` according to `moduli`.
    #[inline]
    pub fn mul<M, A>(mut self, rhs: &DcrtPolynomial<A>, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        self.mul_assign(rhs, poly_length, moduli);
        self
    }

    /// Performs `self *= rhs` according to `moduli`.
    #[inline]
    pub fn mul_assign<M, A>(&mut self, rhs: &DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            moduli
        )
        .for_each(|(a, b, &modulus)| modulus.reduce_mul_slice_assign(a, b))
    }

    /// Inverse butterfly with a precomputed-factor polynomial.
    ///
    /// `(self, result) = (self + rhs, (self_orig - rhs) * w)`.
    ///
    /// `self` and `rhs` are expected in `[0, q)`. Both outputs are written
    /// back in `[0, q)`.
    #[inline]
    pub fn butterfly_mul_factor_to<F, A, B>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
        w: &[F],
        output: &mut DcrtPolynomial<B>,
        poly_length: usize,
        moduli: &[T],
    ) where
        F: Factor<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            w.chunks_exact(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, s, w, b, &modulus)| {
            #[cfg(not(feature = "simd"))]
            slice_butterfly(a, s, w, b, modulus);

            #[cfg(feature = "simd")]
            simd_butterfly(a, s, w, b, modulus);
        })
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs `result = self * rhs` according to `moduli`.
    #[inline]
    pub fn mul_to<M, A, B>(
        &self,
        rhs: &DcrtPolynomial<A>,
        output: &mut DcrtPolynomial<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, b, output, modulus)| modulus.reduce_mul_slice_to(a, b, output))
    }

    /// Performs `result = self * scalar` according to `moduli`.
    #[inline]
    pub fn mul_scalar_to<M, A>(
        &self,
        scalars: &[T],
        output: &mut DcrtPolynomial<A>,
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
        output: &mut DcrtPolynomial<A>,
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
        .for_each(|(in_poly, out_poly, &f, &modulus)| {
            f.factor_mul_slice_to(in_poly, out_poly, modulus)
        })
    }
}

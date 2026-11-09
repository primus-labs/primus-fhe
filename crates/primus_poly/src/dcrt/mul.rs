use itertools::izip;
use primus_data::{Data, DataMut};
use primus_factor::{Factor, FactorMul, FactorSliceOps};
use primus_integer::FheUint;
use primus_modulus::common::compact;
use primus_reduce::{ReduceMulAddSlice, ReduceMulSlice};

#[cfg(feature = "simd")]
use primus_factor::SimdFactorMul;
#[cfg(feature = "simd")]
use primus_integer::SimdArray;

use super::DcrtPolynomial;

// Writes (a+s, (a-s)*w) modulo the current CRT limb's modulus. Preserve the
// original a for the difference; the two outputs are not independent updates.
fn butterfly_mul_factor_slice<T, F>(a: &mut [T], s: &[T], w: &[F], b: &mut [T], modulus: T)
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

// Factors remain scalar-packed: convert each complete vector of factors once,
// then delegate the tail to the same scalar butterfly used without SIMD.
#[cfg(feature = "simd")]
#[allow(clippy::chunks_exact_to_as_chunks)]
fn simd_butterfly_mul_factor_slice<T, F>(a: &mut [T], s: &[T], w: &[F], b: &mut [T], modulus: T)
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

    butterfly_mul_factor_slice(a_rem, s_rem, w_rem, out_rem, modulus);
}

impl<S, T> DcrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self * scalars` according to `moduli`.
    #[must_use]
    #[inline]
    pub fn mul_scalar<M>(mut self, scalars: &[T], poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalars, poly_length, moduli);
        self
    }

    /// Performs `self *= scalars` according to `moduli`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalars: &[T], poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceMulSlice<T>,
    {
        izip!(self.iter_each_modulus_mut(poly_length), scalars, moduli).for_each(
            |(poly, &scalar, &modulus)| modulus.reduce_mul_scalar_slice_assign(poly, scalar),
        )
    }

    /// Performs `self += scalars * rhs` according to `moduli`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
        scalars: &[T],
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
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

    /// Performs `self * factors` according to `moduli`.
    #[must_use]
    #[inline]
    pub fn mul_factor<F>(mut self, factors: &[F], poly_length: usize, moduli: &[T]) -> Self
    where
        F: Copy + FactorSliceOps<T>,
    {
        self.mul_factor_assign(factors, poly_length, moduli);
        self
    }

    /// Performs `self *= factors` according to `moduli`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factors: &[F], poly_length: usize, moduli: &[T])
    where
        F: Copy + FactorSliceOps<T>,
    {
        izip!(self.iter_each_modulus_mut(poly_length), factors, moduli)
            .for_each(|(poly, &factor, &modulus)| factor.factor_mul_slice_assign(poly, modulus))
    }

    /// Performs `self += factors * rhs` according to `moduli`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
        factors: &[F],
        poly_length: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: Data<Elem = T>,
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
    #[must_use]
    #[inline]
    pub fn mul<M, A>(mut self, rhs: &DcrtPolynomial<A>, poly_length: usize, moduli: &[M]) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
        A: Data<Elem = T>,
    {
        self.mul_assign(rhs, poly_length, moduli);
        self
    }

    /// Performs `self *= rhs` according to `moduli`.
    #[inline]
    pub fn mul_assign<M, A>(&mut self, rhs: &DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceMulSlice<T>,
        A: Data<Elem = T>,
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
    /// back in `[0, q)`. `w` is a modulus-major factor polynomial with one
    /// factor per stored point, so its length equals the backing length of each
    /// DCRT polynomial. `output` is overwritten; no scratch is needed.
    ///
    /// # Correctness
    ///
    /// All buffers contain exactly `poly_length * moduli.len()` points, with
    /// nonzero `poly_length` and matching modulus order. Each factor in `w`
    /// must be prepared for its block's modulus and satisfy [`Factor`]'s contract.
    ///
    /// # Panics
    ///
    /// Panics if `poly_length` is zero.
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        let rns_poly_len = self.len();
        debug_assert_eq!(rns_poly_len, rhs.len());
        debug_assert_eq!(rns_poly_len, w.len());
        debug_assert_eq!(rns_poly_len, output.len());
        debug_assert_eq!(rns_poly_len, moduli.len() * poly_length);
        butterfly_mul_factor_to_kernel(
            self.as_mut_view(),
            rhs.as_view(),
            w,
            output.as_mut_view(),
            poly_length,
            moduli,
        );
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: Data<Elem = T>,
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        izip!(
            self.iter_each_modulus(poly_length),
            rhs.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, b, output, modulus)| modulus.reduce_mul_slice_to(a, b, output))
    }

    /// Performs `result = self * scalars` according to `moduli`.
    #[inline]
    pub fn mul_scalar_to<M, A>(
        &self,
        scalars: &[T],
        output: &mut DcrtPolynomial<A>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulSlice<T>,
        A: DataMut<Elem = T>,
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

    /// Performs `result = self * factors` according to `moduli`.
    #[inline]
    pub fn mul_factor_to<F, A>(
        &self,
        factors: &[F],
        output: &mut DcrtPolynomial<A>,
        poly_length: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: DataMut<Elem = T>,
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

// The caller supplies complete modulus-major blocks; the public entry retains
// the shape diagnostics. Each limb uses its own scalar or SIMD butterfly and
// corresponding factor block.
#[inline]
fn butterfly_mul_factor_to_kernel<T, F>(
    mut lhs: DcrtPolynomial<&mut [T]>,
    rhs: DcrtPolynomial<&[T]>,
    w: &[F],
    mut output: DcrtPolynomial<&mut [T]>,
    poly_length: usize,
    moduli: &[T],
) where
    T: FheUint,
    F: Factor<T>,
{
    izip!(
        lhs.iter_each_modulus_mut(poly_length),
        rhs.iter_each_modulus(poly_length),
        w.chunks_exact(poly_length),
        output.iter_each_modulus_mut(poly_length),
        moduli
    )
    .for_each(|(a, s, w, b, &modulus)| {
        #[cfg(not(feature = "simd"))]
        butterfly_mul_factor_slice(a, s, w, b, modulus);

        #[cfg(feature = "simd")]
        simd_butterfly_mul_factor_slice(a, s, w, b, modulus);
    })
}

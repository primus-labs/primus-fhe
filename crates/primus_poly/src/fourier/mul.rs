use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::{FourierPolynomial, FourierPolynomialMut, FourierPolynomialRef};

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Multiplies this Fourier polynomial pointwise by `rhs`.
    #[inline]
    pub fn mul_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        mul_assign_kernel(self.as_mut_view(), rhs.as_view());
    }

    /// Multiplies pointwise by `rhs` and returns this Fourier polynomial.
    #[must_use]
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn mul<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: Data<Elem = Complex64>,
    {
        self.mul_assign(rhs);
        self
    }

    /// Multiplies every Fourier value by the real scalar `scalar` in place.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: f64) {
        mul_scalar_assign_kernel(self.as_mut_view(), scalar);
    }

    /// Multiplies every Fourier value by the real scalar `scalar` and returns
    /// this Fourier polynomial.
    #[must_use]
    #[inline]
    pub fn mul_scalar(mut self, scalar: f64) -> Self {
        self.mul_scalar_assign(scalar);
        self
    }

    /// Accumulates the pointwise product `lhs * rhs` into this polynomial.
    ///
    /// Each real/imaginary component uses two nested fused multiply-adds, without
    /// additional normalization. Results can differ from a separately rounded
    /// complex product followed by addition, including signed-zero and overflow
    /// behavior. NaN bit patterns are unspecified.
    #[inline]
    pub fn add_mul_assign<A, B>(&mut self, lhs: &FourierPolynomial<A>, rhs: &FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: Data<Elem = Complex64>,
    {
        add_mul_assign_kernel(self.as_mut_view(), lhs.as_view(), rhs.as_view());
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes the pointwise product `self * rhs` to `output`.
    #[inline]
    pub fn mul_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        mul_to_kernel(self.as_view(), rhs.as_view(), output.as_mut_view());
    }

    /// Writes the real scalar product `self * scalar` to `output`.
    #[inline]
    pub fn mul_scalar_to<A>(&self, scalar: f64, output: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        mul_scalar_to_kernel(self.as_view(), scalar, output.as_mut_view());
    }
}

#[inline]
fn mul_assign_kernel(mut acc: FourierPolynomialMut<'_>, rhs: FourierPolynomialRef<'_>) {
    debug_assert_eq!(acc.len(), rhs.len());
    for (value, rhs) in acc.iter_mut().zip(rhs.iter()) {
        *value *= *rhs;
    }
}

#[inline]
fn mul_scalar_assign_kernel(mut acc: FourierPolynomialMut<'_>, scalar: f64) {
    for value in acc.iter_mut() {
        *value *= scalar;
    }
}

// Fuse each complex MAC without reordering successive accumulations. Keeping
// real/imaginary lanes interleaved avoids deinterleaving and repacking the vectors.
#[inline]
fn add_mul_assign_kernel(
    acc: FourierPolynomialMut<'_>,
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
) {
    debug_assert_eq!(acc.len(), lhs.len());
    debug_assert_eq!(acc.len(), rhs.len());
    let (acc, lhs, rhs) = (acc.0, lhs.0, rhs.0);
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    let prefix_len = acc.len().min(lhs.len()).min(rhs.len()) & !3;
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
    let prefix_len = 0;

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    {
        use std::arch::x86_64::*;

        let (acc, _) = acc[..prefix_len].as_chunks_mut::<4>();
        let (lhs, _) = lhs[..prefix_len].as_chunks::<4>();
        let (rhs, _) = rhs[..prefix_len].as_chunks::<4>();
        for ((acc, lhs), rhs) in acc.iter_mut().zip(lhs).zip(rhs) {
            // SAFETY: Complex<f64> is repr(C) with adjacent re/im f64 fields.
            // Each array has exactly four complex values (eight doubles); the
            // unaligned loads/stores require no extra alignment. The mutable
            // output cannot alias either input, and cfg guarantees AVX512F.
            unsafe {
                let lhs_re_im = _mm512_loadu_pd(lhs.as_ptr().cast());
                let rhs_re_im = _mm512_loadu_pd(rhs.as_ptr().cast());
                let acc_re_im = _mm512_loadu_pd(acc.as_ptr().cast());
                let lhs_re = _mm512_unpacklo_pd(lhs_re_im, lhs_re_im);
                let lhs_im = _mm512_unpackhi_pd(lhs_re_im, lhs_re_im);
                let rhs_im_re = _mm512_permute_pd::<0b01010101>(rhs_re_im);
                // Even lanes subtract, odd lanes add: the inner real lane is
                // ai*bi - cr, which the outer FMA subtracts from ar*br.
                let inner = _mm512_fmaddsub_pd(lhs_im, rhs_im_re, acc_re_im);
                let result = _mm512_fmaddsub_pd(lhs_re, rhs_re_im, inner);
                _mm512_storeu_pd(acc.as_mut_ptr().cast(), result);
            }
        }
    }
    // Match the SIMD signs and nesting, including signed-zero behavior.
    for ((value, lhs), rhs) in acc[prefix_len..]
        .iter_mut()
        .zip(lhs[prefix_len..].iter())
        .zip(rhs[prefix_len..].iter())
    {
        let re_product = lhs.im.mul_add(rhs.im, -value.re);
        let im_product = lhs.im.mul_add(rhs.re, value.im);
        value.re = lhs.re.mul_add(rhs.re, -re_product);
        value.im = lhs.re.mul_add(rhs.im, im_product);
    }
}

#[inline]
fn mul_to_kernel(
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(lhs.len(), rhs.len());
    debug_assert_eq!(lhs.len(), output.len());
    for ((output, lhs), rhs) in output.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *output = *lhs * *rhs;
    }
}

#[inline]
fn mul_scalar_to_kernel(
    input: FourierPolynomialRef<'_>,
    scalar: f64,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(input.len(), output.len());
    for (output, value) in output.iter_mut().zip(input.iter()) {
        *output = *value * scalar;
    }
}

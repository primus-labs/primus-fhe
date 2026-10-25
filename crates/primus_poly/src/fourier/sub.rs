use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::{FourierPolynomial, FourierPolynomialMut, FourierPolynomialRef};

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Subtracts `rhs` pointwise from this Fourier polynomial.
    #[inline]
    pub fn sub_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        sub_assign_kernel(self.as_mut_view(), rhs.as_view());
    }

    /// Subtracts `rhs` pointwise and returns this Fourier polynomial.
    #[must_use]
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn sub<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: Data<Elem = Complex64>,
    {
        self.sub_assign(rhs);
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Replaces `rhs` with the pointwise difference `self - rhs`.
    #[inline]
    pub fn sub_rev_assign<A>(&self, rhs: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        sub_rev_assign_kernel(self.as_view(), rhs.as_mut_view());
    }

    /// Writes the pointwise difference `self - rhs` to `output`.
    #[inline]
    pub fn sub_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        sub_to_kernel(self.as_view(), rhs.as_view(), output.as_mut_view());
    }
}

#[inline]
fn sub_assign_kernel(mut acc: FourierPolynomialMut<'_>, rhs: FourierPolynomialRef<'_>) {
    debug_assert_eq!(acc.len(), rhs.len());
    for (value, rhs) in acc.iter_mut().zip(rhs.iter()) {
        *value -= *rhs;
    }
}

#[inline]
fn sub_rev_assign_kernel(lhs: FourierPolynomialRef<'_>, mut rhs: FourierPolynomialMut<'_>) {
    debug_assert_eq!(lhs.len(), rhs.len());
    for (rhs, lhs) in rhs.iter_mut().zip(lhs.iter()) {
        *rhs = *lhs - *rhs;
    }
}

#[inline]
fn sub_to_kernel(
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(lhs.len(), rhs.len());
    debug_assert_eq!(lhs.len(), output.len());
    for ((output, lhs), rhs) in output.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *output = *lhs - *rhs;
    }
}

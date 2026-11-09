use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::{FourierPolynomial, FourierPolynomialMut, FourierPolynomialRef};

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Adds `rhs` pointwise to this Fourier polynomial.
    #[inline]
    pub fn add_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        add_assign_kernel(self.as_mut_view(), rhs.as_view());
    }

    /// Adds `rhs` pointwise and returns this Fourier polynomial.
    #[must_use]
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: Data<Elem = Complex64>,
    {
        self.add_assign(rhs);
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes the pointwise sum `self + rhs` to `output`.
    #[inline]
    pub fn add_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        add_to_kernel(self.as_view(), rhs.as_view(), output.as_mut_view());
    }
}

#[inline]
fn add_assign_kernel(mut acc: FourierPolynomialMut<'_>, rhs: FourierPolynomialRef<'_>) {
    debug_assert_eq!(acc.len(), rhs.len());
    for (value, rhs) in acc.iter_mut().zip(rhs.iter()) {
        *value += *rhs;
    }
}

#[inline]
fn add_to_kernel(
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(lhs.len(), rhs.len());
    debug_assert_eq!(lhs.len(), output.len());
    for ((output, lhs), rhs) in output.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *output = *lhs + *rhs;
    }
}

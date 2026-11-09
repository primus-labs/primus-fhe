use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::{FourierPolynomial, FourierPolynomialMut, FourierPolynomialRef};

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Negates every value in this Fourier polynomial.
    #[inline]
    pub fn neg_assign(&mut self) {
        neg_assign_kernel(self.as_mut_view());
    }

    /// Negates every value and returns this Fourier polynomial.
    #[must_use]
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn neg(mut self) -> Self {
        self.neg_assign();
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes the pointwise negation of `self` to `output`.
    #[inline]
    pub fn neg_to<A>(&self, output: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        neg_to_kernel(self.as_view(), output.as_mut_view());
    }
}

#[inline]
fn neg_assign_kernel(mut acc: FourierPolynomialMut<'_>) {
    for value in acc.iter_mut() {
        *value = -*value;
    }
}

#[inline]
fn neg_to_kernel(input: FourierPolynomialRef<'_>, mut output: FourierPolynomialMut<'_>) {
    debug_assert_eq!(input.len(), output.len());
    for (output, value) in output.iter_mut().zip(input.iter()) {
        *output = -*value;
    }
}

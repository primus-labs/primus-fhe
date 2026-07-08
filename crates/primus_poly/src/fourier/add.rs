use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Performs `self + rhs` (pointwise complex addition).
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: RawData<Elem = Complex64> + Data,
    {
        self.add_assign(rhs);
        self
    }

    /// Performs `self += rhs` (pointwise complex addition in place).
    #[inline]
    pub fn add_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: RawData<Elem = Complex64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        for (a, &b) in self.iter_mut().zip(rhs.iter()) {
            *a += b;
        }
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Performs `output = self + rhs` (pointwise complex addition).
    #[inline]
    pub fn add_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        for ((&a, &b), out) in self.iter().zip(rhs.iter()).zip(output.iter_mut()) {
            *out = a + b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fourier::FourierPolynomialOwned;

    #[test]
    fn test_add_assign() {
        let a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(1.0, 0.0),
            Complex64::new(2.0, 1.0),
        ]);
        let b = FourierPolynomialOwned::from_slice(&[
            Complex64::new(3.0, 0.0),
            Complex64::new(0.0, 1.0),
        ]);
        let mut result = a;
        result.add_assign(&b);
        assert_eq!(result.as_slice()[0], Complex64::new(4.0, 0.0));
        assert_eq!(result.as_slice()[1], Complex64::new(2.0, 2.0));
    }

    #[test]
    fn test_add_to() {
        let a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(1.0, 0.0),
            Complex64::new(0.0, 0.0),
        ]);
        let b = FourierPolynomialOwned::from_slice(&[
            Complex64::new(0.0, 0.0),
            Complex64::new(0.0, 1.0),
        ]);
        let mut output = FourierPolynomialOwned::zero(2);
        a.add_to(&b, &mut output);
        assert_eq!(output.as_slice()[0], Complex64::new(1.0, 0.0));
        assert_eq!(output.as_slice()[1], Complex64::new(0.0, 1.0));
    }
}

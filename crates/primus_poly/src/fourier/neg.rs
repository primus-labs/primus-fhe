use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Performs the unary `-` operation (pointwise complex negation).
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn neg(mut self) -> Self {
        self.neg_assign();
        self
    }

    /// Performs the unary `-` operation in place.
    #[inline]
    pub fn neg_assign(&mut self) {
        for a in self.iter_mut() {
            *a = -*a;
        }
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Performs `output = -self` (pointwise complex negation).
    #[inline]
    pub fn neg_to<A>(&self, output: &mut FourierPolynomial<A>)
    where
        A: RawData<Elem = Complex64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        for (&a, out) in self.iter().zip(output.iter_mut()) {
            *out = -a;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fourier::FourierPolynomialOwned;

    #[test]
    fn test_neg_assign() {
        let mut a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(1.0, 2.0),
            Complex64::new(-3.0, 0.0),
        ]);
        a.neg_assign();
        assert_eq!(a.as_slice()[0], Complex64::new(-1.0, -2.0));
        assert_eq!(a.as_slice()[1], Complex64::new(3.0, 0.0));
    }

    #[test]
    fn test_neg_to() {
        let a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(1.0, -1.0),
            Complex64::new(0.0, 2.0),
        ]);
        let mut output = FourierPolynomialOwned::zero(2);
        a.neg_to(&mut output);
        assert_eq!(output.as_slice()[0], Complex64::new(-1.0, 1.0));
        assert_eq!(output.as_slice()[1], Complex64::new(0.0, -2.0));
    }
}

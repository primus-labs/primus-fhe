use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Performs `self * rhs` (pointwise complex multiplication).
    #[inline]
    pub fn mul<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: RawData<Elem = Complex64> + Data,
    {
        self.mul_assign(rhs);
        self
    }

    /// Performs `self *= rhs` (pointwise complex multiplication in place).
    #[inline]
    pub fn mul_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: RawData<Elem = Complex64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        for (a, &b) in self.iter_mut().zip(rhs.iter()) {
            *a *= b;
        }
    }

    /// Performs `self += lhs * rhs` (fused multiply-add) in place.
    ///
    /// This is the hot-path accumulation used in TFHE external product and
    /// CMUX operations.
    #[inline]
    pub fn add_mul_assign<A, B>(&mut self, lhs: &FourierPolynomial<A>, rhs: &FourierPolynomial<B>)
    where
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = Complex64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), lhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        for ((acc, &l), &r) in self.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
            *acc += l * r;
        }
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Performs `output = self * rhs` (pointwise complex multiplication).
    #[inline]
    pub fn mul_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        for ((&a, &b), out) in self.iter().zip(rhs.iter()).zip(output.iter_mut()) {
            *out = a * b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fourier::FourierPolynomialOwned;

    #[test]
    fn test_mul_assign() {
        let a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(2.0, 0.0),
            Complex64::new(0.0, 1.0),
        ]);
        let b = FourierPolynomialOwned::from_slice(&[
            Complex64::new(3.0, 0.0),
            Complex64::new(1.0, 0.0),
        ]);
        let mut result = a;
        result.mul_assign(&b);
        assert_eq!(result.as_slice()[0], Complex64::new(6.0, 0.0));
        // (i) * 1 = i
        assert_eq!(result.as_slice()[1], Complex64::new(0.0, 1.0));
    }

    #[test]
    fn test_add_mul_assign() {
        // acc starts as [1, 1], lhs = [2, i], rhs = [3, 1]
        // acc += lhs * rhs => [1+2*3, 1+i*1] = [7, 1+i]
        let mut acc = FourierPolynomialOwned::from_slice(&[
            Complex64::new(1.0, 0.0),
            Complex64::new(1.0, 0.0),
        ]);
        let lhs = FourierPolynomialOwned::from_slice(&[
            Complex64::new(2.0, 0.0),
            Complex64::new(0.0, 1.0),
        ]);
        let rhs = FourierPolynomialOwned::from_slice(&[
            Complex64::new(3.0, 0.0),
            Complex64::new(1.0, 0.0),
        ]);
        acc.add_mul_assign(&lhs, &rhs);
        assert_eq!(acc.as_slice()[0], Complex64::new(7.0, 0.0));
        assert_eq!(acc.as_slice()[1], Complex64::new(1.0, 1.0));
    }

    #[test]
    fn test_mul_to() {
        let a = FourierPolynomialOwned::from_slice(&[
            Complex64::new(2.0, 0.0),
            Complex64::new(0.0, 1.0),
        ]);
        let b = FourierPolynomialOwned::from_slice(&[
            Complex64::new(3.0, 0.0),
            Complex64::new(1.0, 0.0),
        ]);
        let mut output = FourierPolynomialOwned::zero(2);
        a.mul_to(&b, &mut output);
        assert_eq!(output.as_slice()[0], Complex64::new(6.0, 0.0));
        assert_eq!(output.as_slice()[1], Complex64::new(0.0, 1.0));
    }
}

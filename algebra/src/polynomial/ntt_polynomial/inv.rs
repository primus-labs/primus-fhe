use num_traits::Inv;

use crate::Field;

use super::NTTPolynomial;

impl<F: Field> Inv for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn inv(mut self) -> Self::Output {
        self.iter_mut().for_each(|v| *v = v.inv());
        self
    }
}

impl<F: Field> Inv for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn inv(self) -> Self::Output {
        let data = self.iter().map(|v| v.inv()).collect();
        NTTPolynomial::new(data)
    }
}

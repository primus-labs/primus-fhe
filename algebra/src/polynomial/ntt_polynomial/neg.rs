use std::ops::Neg;

use super::NTTPolynomial;

impl<F: Copy + Neg<Output = F>> NTTPolynomial<F> {
    /// Performs the unary `-` operation.
    #[inline]
    pub fn neg_assign(&mut self) {
        self.data.iter_mut().for_each(|v| *v = -*v);
    }
}

impl<F: Copy + Neg<Output = F>> Neg for NTTPolynomial<F> {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self::Output {
        self.iter_mut().for_each(|e| {
            *e = -*e;
        });
        self
    }
}

impl<F: Copy + Neg<Output = F>> Neg for &NTTPolynomial<F> {
    type Output = NTTPolynomial<F>;

    #[inline]
    fn neg(self) -> Self::Output {
        let data = self.iter().map(|&e| -e).collect();
        <NTTPolynomial<F>>::new(data)
    }
}

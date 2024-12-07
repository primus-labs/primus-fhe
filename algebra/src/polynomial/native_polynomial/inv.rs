use num_traits::Inv;

use crate::NTTField;

use super::Polynomial;

impl<F: NTTField> Inv for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn inv(self) -> Self::Output {
        self.into_ntt_polynomial().inv().into_native_polynomial()
    }
}

impl<F: NTTField> Inv for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn inv(self) -> Self::Output {
        self.clone()
            .into_ntt_polynomial()
            .inv()
            .into_native_polynomial()
    }
}

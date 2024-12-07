use crate::{transformation::AbstractNTT, NTTField, NTTPolynomial};

use super::Polynomial;

impl<F: NTTField> From<NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn from(ntt_polynomial: NTTPolynomial<F>) -> Self {
        debug_assert!(ntt_polynomial.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(ntt_polynomial.coeff_count().trailing_zeros()).unwrap();

        ntt_table.inverse_transform_inplace(ntt_polynomial)
    }
}

impl<F: NTTField> Polynomial<F> {
    /// Convert `self` from [`Polynomial<F>`] to [`NTTPolynomial<F>`].
    #[inline]
    pub fn into_ntt_polynomial(self) -> NTTPolynomial<F> {
        <NTTPolynomial<F>>::from(self)
    }
}

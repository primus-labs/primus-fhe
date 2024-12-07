use crate::{transformation::AbstractNTT, NTTField, Polynomial};

use super::NTTPolynomial;

impl<F: NTTField> From<Polynomial<F>> for NTTPolynomial<F> {
    #[inline]
    fn from(polynomial: Polynomial<F>) -> Self {
        debug_assert!(polynomial.coeff_count().is_power_of_two());

        let ntt_table = F::get_ntt_table(polynomial.coeff_count().trailing_zeros()).unwrap();

        ntt_table.transform_inplace(polynomial)
    }
}

impl<F: NTTField> NTTPolynomial<F> {
    /// Convert `self` from [`NTTPolynomial<F>`] to [`Polynomial<F>`]
    #[inline]
    pub fn into_native_polynomial(self) -> Polynomial<F> {
        <Polynomial<F>>::from(self)
    }
}

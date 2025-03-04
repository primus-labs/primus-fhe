use crate::{ntt::NumberTheoryTransform, polynomial::FieldPolynomial, NttField};

use super::FieldNttPolynomial;

impl<F: NttField> FieldNttPolynomial<F> {
    /// Converts [`FieldNttPolynomial<F>`] into [`FieldPolynomial<F>`].
    #[inline]
    pub fn into_coeff_poly(mut self, ntt_table: &<F as NttField>::Table) -> FieldPolynomial<F> {
        ntt_table.inverse_transform_slice(self.as_mut_slice());
        FieldPolynomial::new(self.data)
    }
}

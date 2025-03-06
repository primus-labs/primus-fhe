use crate::{ntt::NumberTheoryTransform, polynomial::FieldNttPolynomial, NttField};

use super::FieldPolynomial;

impl<F: NttField> FieldPolynomial<F> {
    /// Converts [`FieldPolynomial<F>`] into [`FieldNttPolynomial<F>`].
    #[inline]
    pub fn into_ntt_poly(mut self, ntt_table: &<F as NttField>::Table) -> FieldNttPolynomial<F> {
        ntt_table.transform_slice(self.as_mut_slice());
        FieldNttPolynomial::new(self.data)
    }
}

use crate::{
    ntt::{NttTable, NumberTheoryTransform},
    numeric::Numeric,
    polynomial::Polynomial,
};

use super::NttPolynomial;

impl<T: Numeric> NttPolynomial<T> {
    /// Converts [`NttPolynomial<T>`] into [`Polynomial<T>`].
    #[inline]
    pub fn into_coeff_poly<Table>(mut self, ntt_table: &Table) -> Polynomial<T>
    where
        Table: NttTable<ValueT = T>
            + NumberTheoryTransform<CoeffPoly = Polynomial<T>, NttPoly = NttPolynomial<T>>,
    {
        ntt_table.inverse_transform_slice(self.as_mut_slice());
        Polynomial::new(self.values)
    }
}

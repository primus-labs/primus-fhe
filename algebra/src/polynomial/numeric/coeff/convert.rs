use crate::{
    ntt::{NttTable, NumberTheoryTransform},
    numeric::Numeric,
    polynomial::NttPolynomial,
};

use super::Polynomial;

impl<T: Numeric> Polynomial<T> {
    /// Converts [`Polynomial<T>`] into [`NttPolynomial<T>`].
    #[inline]
    pub fn into_ntt_poly<Table>(mut self, ntt_table: &Table) -> NttPolynomial<T>
    where
        Table: NttTable<ValueT = T>
            + NumberTheoryTransform<CoeffPoly = Self, NttPoly = NttPolynomial<T>>,
    {
        ntt_table.transform_slice(self.as_mut_slice());
        NttPolynomial::new(self.poly)
    }
}

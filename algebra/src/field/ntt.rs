use crate::{
    ntt::{NttTable, NumberTheoryTransform},
    polynomial::{FieldNttPolynomial, FieldPolynomial},
};

use super::Field;

/// Extended the [Field] to [NttField], enables fast polynomial multiplication.
pub trait NttField: Field {
    /// An abstraction over the data structure used to store precomputed values for NTT.
    type Table: NttTable<ValueT = Self::ValueT>
        + NumberTheoryTransform<CoeffPoly = FieldPolynomial<Self>, NttPoly = FieldNttPolynomial<Self>>;

    /// Generate the ntt table of the ntt field with desired `log_n`.
    fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError>;
}

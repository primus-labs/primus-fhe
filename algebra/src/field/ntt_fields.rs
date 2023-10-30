//! Define `NTTField`` trait

use super::PrimeField;

/// A helper trait  for number theory transform
///
/// It's optimized for the vector with the length of power of two.
pub trait NTTField: PrimeField {
    /// NTT table type
    type NTTTable;
}

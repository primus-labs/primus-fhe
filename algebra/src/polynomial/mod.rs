//! Defines polynomial.

mod field;
mod numeric;

pub use field::{FieldNttPolynomial, FieldPolynomial};
pub use numeric::{NttPolynomial, Polynomial};

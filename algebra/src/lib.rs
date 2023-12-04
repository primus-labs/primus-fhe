#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

mod error;

pub mod derive;

pub mod field;
pub mod modulo_traits;
pub mod modulus;
pub mod ring;
pub mod utils;

pub mod polynomial;
pub mod transformation;

mod primitive;

pub use error::AlgebraError;

pub use primitive::{div_ceil, Bits, Widening};

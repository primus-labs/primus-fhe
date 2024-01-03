#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

mod error;

pub mod derive;

mod basis;
mod field;
pub mod modulus;
mod random;
pub mod reduce;
mod ring;
pub mod utils;

mod polynomial;
pub mod transformation;

mod primitive;

pub use error::AlgebraError;

pub use basis::Basis;
pub use field::{Field, MulFactor, NTTField, PrimeField, RandomNTTField};
pub use random::Random;
pub use reduce::ModulusConfig;
pub use ring::{RandomRing, Ring};

pub use polynomial::{NTTPolynomial, Polynomial};

pub use primitive::{div_ceil, Bits, RoundedDiv, Widening};

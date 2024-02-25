#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

mod error;

pub mod derive;

mod decompose_basis;
mod field;
pub mod modulus;
mod random;
pub mod reduce;
pub mod utils;

mod polynomial;
pub mod transformation;

mod primitive;

pub use error::AlgebraError;

pub use decompose_basis::Basis;
pub use field::{Field, MulFactor, NTTField, PrimeField, RandomNTTField};
pub use random::Random;
pub use reduce::ModulusConfig;

pub use polynomial::{
    ntt_add_mul_assign, ntt_add_mul_assign_ref, ntt_mul_assign, ntt_mul_assign_ref, NTTPolynomial,
    Polynomial,
};

pub use primitive::{div_ceil, Bits, Widening};

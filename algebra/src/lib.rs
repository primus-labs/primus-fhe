#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

mod decompose_basis;
mod error;
mod field;
mod polynomial;
mod primitive;
mod random;

pub mod derive;
pub mod modulus;
pub mod reduce;
pub mod transformation;
pub mod utils;

pub use decompose_basis::Basis;
pub use error::AlgebraError;
pub use field::{Field, NTTField, PrimeField, RandomNTTField};
pub use polynomial::multivariate::{
    DenseMultilinearExtension, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
};
pub use polynomial::univariate::{
    ntt_add_mul_assign, ntt_add_mul_assign_fast, ntt_add_mul_inplace, ntt_mul_assign,
    ntt_mul_inplace, NTTPolynomial, Polynomial,
};
pub use primitive::{div_ceil, Bits, Widening, WrappingOps};
pub use random::{FieldBinarySampler, FieldDiscreteGaussianSampler, FieldTernarySampler, Random};
pub use reduce::ModulusConfig;

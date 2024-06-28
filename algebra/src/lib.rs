#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

mod baby_bear;
mod decompose_basis;
mod error;
mod extension;
mod field;
mod goldilocks;
mod polynomial;
mod primitive;
mod random;

pub mod derive;
pub mod modulus;
pub mod reduce;
pub mod transformation;
pub mod utils;

pub use baby_bear::{BabyBear, BabyBearExetension};
pub use decompose_basis::Basis;
pub use error::AlgebraError;
pub use extension::*;
pub use field::{DecomposableField, FheField, Field, NTTField, PrimeField};
pub use goldilocks::{Goldilocks, GoldilocksExtension};
pub use polynomial::multivariate::{
    DenseMultilinearExtension, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
};
pub use polynomial::univariate::{
    ntt_add_mul_assign, ntt_add_mul_assign_fast, ntt_add_mul_inplace, ntt_mul_assign,
    ntt_mul_inplace, NTTPolynomial, Polynomial,
};
pub use primitive::{div_ceil, AsFrom, AsInto, Bits, Widening, WrappingOps};
pub use random::{
    FieldBinarySampler, FieldDiscreteGaussianSampler, FieldTernarySampler, FieldUniformSampler,
};
pub use reduce::ModulusConfig;

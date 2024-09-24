#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.
#[cfg(feature = "concrete-ntt")]
mod baby_bear;

#[cfg(feature = "concrete-ntt")]
mod goldilocks;

mod decompose_basis;
mod error;
mod extension;
mod field;
mod polynomial;
mod primitive;
mod random;

pub mod derive;
pub mod modulus;
pub mod reduce;
pub mod transformation;
pub mod utils;

#[cfg(feature = "concrete-ntt")]
pub use baby_bear::{BabyBear, BabyBearExetension};

#[cfg(feature = "concrete-ntt")]
pub use goldilocks::{Goldilocks, GoldilocksExtension};

pub use decompose_basis::Basis;
pub use error::AlgebraError;
pub use extension::*;
pub use field::{DecomposableField, FheField, Field, NTTField, PrimeField};
pub use polynomial::multivariate::{
    DenseMultilinearExtension, ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
    SparsePolynomial,
};
pub use polynomial::univariate::{
    ntt_add_mul_assign, ntt_add_mul_assign_fast, ntt_add_mul_inplace, NTTPolynomial, Polynomial,
};
pub use primitive::*;
pub use random::{
    FieldBinarySampler, FieldDiscreteGaussianSampler, FieldTernarySampler, FieldUniformSampler,
};
pub use reduce::ModulusConfig;

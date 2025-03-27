#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
#![cfg_attr(feature = "nightly", feature(bigint_helper_methods))]

//! Basic algebra abstract and some operations for it.

mod error;

pub mod arith;
pub mod decompose;
pub mod integer;
pub mod numeric;

pub mod modulus;
pub mod reduce;

mod field;

pub mod random;

pub mod ntt;
pub mod polynomial;

pub mod utils;

pub use error::AlgebraError;

pub use field::*;
pub use integer::*;

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.
pub mod bit_decomposition;
pub mod sumcheck;

pub use error::Error;
mod error;

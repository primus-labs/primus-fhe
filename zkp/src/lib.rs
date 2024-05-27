#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.
pub mod piop;
pub mod sumcheck;
pub mod utils;

pub use error::Error;
mod error;

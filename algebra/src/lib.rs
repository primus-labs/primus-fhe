#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Define arithmetic operations.

pub mod field;
pub mod modulo;
pub mod utils;

pub mod error;

pub mod polynomial;

mod primitive;

pub(crate) use primitive::{Bits, Widening};

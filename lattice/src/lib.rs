#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This crate defines some concrete struct types
//! for LWE and RLWE.

mod lwe;
mod rgsw;
mod rlwe;
mod util;

pub use lwe::LWE;
pub use rgsw::RGSW;
pub use rlwe::{GadgetRLWE, RLWE};

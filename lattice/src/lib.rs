#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This crate defines some concrete struct types
//! for LWE, RLWE, RGSW.

mod gadget;
mod lwe;
mod rgsw;
mod rlwe;

pub use gadget::GadgetRLWE;
pub use lwe::LWE;
pub use rgsw::RGSW;
pub use rlwe::RLWE;

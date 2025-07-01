#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Defines some lattice cryptographic structure.

mod gadget;
mod lwe;
mod rgsw;
mod rlwe;

pub mod utils;

pub use gadget::{GadgetRlwe, NttGadgetRlwe};
pub use lwe::{CmLwe, Lwe};
pub use rgsw::{NttRgsw, Rgsw};
pub use rlwe::{NttRlwe, NumRlwe, Rlwe, SparseRlwe};

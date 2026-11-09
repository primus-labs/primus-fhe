//! Scheme-owned evaluation keys in native `[c0,c1]` plus-phase order.
//! Radix keys live in Q; Hybrid keys live in QP and divide by P only inside
//! their native key product. No ordinary operation crosses a raw GLWE bridge.

pub use primus_lattice::hybrid::EvaluationKeyConfig as BfvEvaluationKeyConfig;

mod apply;
mod backend;
mod collective;
mod error;
mod generate;
mod material;
mod persistence;
mod product;
mod working;

pub use apply::{BfvAutomorphism, BfvKeySwitcher, BfvRelinearizer};
pub use collective::*;
pub use error::BfvEvaluationKeyError;
pub use material::{BfvAutomorphismKey, BfvKeySwitchingKey, BfvRelinearizationKey};

#[cfg(test)]
mod tests;

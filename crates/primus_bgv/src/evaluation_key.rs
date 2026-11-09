//! Native p-preserving gadget keys in physical `[c0,c1]` order.

/// Scheme key decomposition selection for signed Radix and native Hybrid.
pub use primus_lattice::hybrid::EvaluationKeyConfig as BgvEvaluationKeyConfig;

mod apply;
mod backend;
mod collective;
mod error;
mod generate;
mod material;
mod persistence;
mod product;

pub use apply::{BgvAutomorphism, BgvKeySwitcher, BgvRelinearizer};
pub use collective::*;
pub use error::BgvEvaluationKeyError;
pub use material::{BgvAutomorphismKey, BgvKeySwitchingKey, BgvRelinearizationKey};

#[cfg(test)]
mod tests;

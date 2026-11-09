//! RNS GLWE key-switching implementations.

mod dcrt;
mod hybrid;

pub use dcrt::{DcrtGlweKeySwitchEvaluator, DcrtGlweKeySwitchingKey};
pub use hybrid::{HybridRnsGlweKeySwitchEvaluator, HybridRnsGlweKeySwitchingKey};

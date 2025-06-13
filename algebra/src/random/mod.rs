//! Defines some algorithms for random values generation.

mod dg;
mod numeric;
mod prg;

pub use dg::CumulativeDistributionTableSampler;
pub use numeric::*;
pub use prg::{Aes, Prg};

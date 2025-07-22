//! Defines some algorithms for random values generation.

mod discrete_gaussian;
mod numeric;
mod prg;

#[cfg(target_os = "linux")]
pub use discrete_gaussian::UnixCDTSampler;
pub use discrete_gaussian::{CDTSampler, DiscreteZiggurat};
pub use numeric::*;
pub use prg::{Aes, Prg};

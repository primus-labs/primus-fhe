//! Defines some algorithms for random values generation.

mod numeric;
mod prg;

pub use numeric::*;
pub use prg::{Aes, Prg};

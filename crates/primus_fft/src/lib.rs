#![deny(missing_docs)]
//! Negacyclic FFT wrappers for `Z[X] / (X^N + 1)`.
//!
//! The default build provides [`FftTable`], [`FftEngine`], and torus conversions.
//! Enable `rustfft` or `tfhe-fft` for a bundled implementation; both may coexist.

#[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
mod automorphism;
mod table;
mod torus;

mod backend;

pub use num_complex::Complex64;
pub use table::{FftEngine, FftTable};
pub use torus::TorusFftValue;

#[cfg(feature = "rustfft")]
pub use backend::{RustFftTable, RustFftWorkspace};
#[cfg(feature = "tfhe-fft")]
pub use backend::{TfheFftTable, TfheFftWorkspace};

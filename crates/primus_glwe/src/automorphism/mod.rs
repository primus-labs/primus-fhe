//! Homomorphic automorphisms with representation-specific evaluation keys.

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::{FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace};
#[cfg(feature = "ntt")]
pub use ntt::{NttGlweAutomorphismKey, NttGlweAutomorphismWorkspace};

//! Homomorphic automorphisms of scalar NTRU ciphertexts.

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::{FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace};
#[cfg(feature = "ntt")]
pub use ntt::{NttNtruAutomorphismKey, NttNtruAutomorphismWorkspace};

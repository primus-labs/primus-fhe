//! Homomorphic automorphisms of scalar NTRU ciphertexts.

#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "ntt")]
pub use ntt::{NttNtruAutomorphismKey, NttNtruAutomorphismWorkspace};

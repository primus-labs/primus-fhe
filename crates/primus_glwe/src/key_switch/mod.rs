//! GLWE key switching across single-modulus and RNS representations.

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::{FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace};
#[cfg(feature = "ntt")]
pub use ntt::{NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace};

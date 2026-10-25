//! Trace, normalized reverse trace, coefficient projection and expansion.

#[cfg(feature = "fourier")]
mod fourier;
mod kernels;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::{FourierNtruTraceKey, FourierNtruTraceWorkspace};
#[cfg(feature = "ntt")]
pub use ntt::{NttNtruTraceKey, NttNtruTraceWorkspace};

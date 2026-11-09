//! Trace, coefficient projection and related-key packing.
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "fourier")]
mod fourier_operations;
mod kernels;
#[cfg(feature = "ntt")]
mod ntt;
#[cfg(feature = "ntt")]
mod ntt_operations;

#[cfg(feature = "fourier")]
pub use fourier::{FourierGlweTraceKey, FourierGlweTraceWorkspace};
#[cfg(feature = "fourier")]
pub use fourier_operations::FourierGlwePackingWorkspace;
#[cfg(feature = "ntt")]
pub use ntt::{NttGlweTraceKey, NttGlweTraceWorkspace};
#[cfg(feature = "ntt")]
pub use ntt_operations::NttGlwePackingWorkspace;

#[cfg(feature = "split-trace")]
mod split;
#[cfg(feature = "split-trace")]
pub use split::{SplitFourierGlweTraceKey, SplitFourierGlweTraceWorkspace};

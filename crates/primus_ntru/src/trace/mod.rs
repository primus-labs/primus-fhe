//! Trace, normalized reverse trace, coefficient projection and expansion.

mod kernels;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "ntt")]
pub use ntt::{NttNtruTraceKey, NttNtruTraceWorkspace};

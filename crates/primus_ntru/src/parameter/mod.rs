//! NTRU parameters grouped by sampling, ordinary encoding and gadget roles.

mod core;
mod error;
mod gadget;
mod ordinary;

pub use core::NtruEncryptionParameters;
pub use error::{NlevParameterError, NtruParameterError};
pub use gadget::NlevParameters;
pub use ordinary::NtruParameters;

/// Maximum candidates in a backend's invertible-key search.
#[cfg(any(feature = "ntt", feature = "fourier"))]
pub(crate) const KEY_GENERATION_ATTEMPTS: usize = 1 << 10;

//! RNS GLWE sampling, gadget precomputation and compatibility checks.

mod core;
mod domain;
mod error;
mod gadget;

pub use core::CrtGlweEncryptionParameters;
pub use domain::RnsDomainError;
pub use error::{CrtGlevParametersError, CrtGlweEncryptionParametersError};
pub use gadget::{CrtGgswParameters, CrtGlevParameters};

pub(crate) use domain::{validate_dcrt_table, validate_glwe_size, validate_moduli};

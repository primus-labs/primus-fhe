//! GLWE parameters grouped by encryption, gadget and key-switch roles.

mod core;
mod error;
mod gadget;
mod key_switch;
mod ordinary;

pub use core::GlweEncryptionParameters;
pub use error::{GlevParameterError, GlweParameterError};
pub use gadget::{GgswParameters, GlevParameters};
pub use key_switch::GlweKeySwitchingParameters;
pub use ordinary::GlweParameters;
pub use primus_lattice::{GadgetSize, GlweSize, GlweSizeError};

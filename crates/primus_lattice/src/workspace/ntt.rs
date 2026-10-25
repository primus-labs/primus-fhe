//! NTT operation workspaces.

mod glwe_external_product;
mod glwe_ternary_cmux;
mod ntru_cmux;
mod ntru_external_product;

pub use glwe_external_product::NttGlweExternalProductWorkspace;
pub(crate) use glwe_external_product::NttGlweExternalProductWorkspaceRefMut;
pub use glwe_ternary_cmux::NttGlweTernaryCmuxWorkspace;
pub use ntru_cmux::NttNtruCmuxWorkspace;
pub use ntru_external_product::NttNtruExternalProductWorkspace;
pub(crate) use ntru_external_product::NttNtruExternalProductWorkspaceRefMut;

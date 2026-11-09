//! Fourier operation workspaces.

mod glwe_external_product;
mod glwe_ternary_cmux;

pub use glwe_external_product::FourierGlweExternalProductWorkspace;
pub(crate) use glwe_external_product::FourierGlweExternalProductWorkspaceRefMut;
pub use glwe_ternary_cmux::FourierGlweTernaryCmuxWorkspace;

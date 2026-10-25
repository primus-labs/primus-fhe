//! Fourier operation workspaces.

mod glwe_external_product;
mod glwe_ternary_cmux;
mod ntru_split;
pub use ntru_split::FourierNtruSplitWorkspace;
mod ntru_cmux;
mod ntru_external_product;

pub use glwe_external_product::FourierGlweExternalProductWorkspace;
pub(crate) use glwe_external_product::FourierGlweExternalProductWorkspaceRefMut;
pub use glwe_ternary_cmux::FourierGlweTernaryCmuxWorkspace;
pub use ntru_cmux::FourierNtruCmuxWorkspace;
pub use ntru_external_product::FourierNtruExternalProductWorkspace;
pub(crate) use ntru_external_product::FourierNtruExternalProductWorkspaceRefMut;

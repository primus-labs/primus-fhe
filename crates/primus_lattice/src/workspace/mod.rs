//! Reusable scratch storage, grouped internally by transform representation.

#[cfg(feature = "rns")]
mod dcrt_glev_mul;
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "rns")]
pub use dcrt_glev_mul::DcrtGlevMulWorkspace;
#[cfg(feature = "rns")]
pub(crate) use dcrt_glev_mul::DcrtGlevMulWorkspaceRefMut;

#[cfg(feature = "fourier")]
pub use fourier::{
    FourierGlweExternalProductWorkspace, FourierGlweTernaryCmuxWorkspace, FourierNtruCmuxWorkspace,
    FourierNtruExternalProductWorkspace, FourierNtruSplitWorkspace,
};
#[cfg(feature = "fourier")]
pub(crate) use fourier::{
    FourierGlweExternalProductWorkspaceRefMut, FourierNtruExternalProductWorkspaceRefMut,
};
#[cfg(feature = "ntt")]
pub use ntt::{
    NttGlweExternalProductWorkspace, NttGlweTernaryCmuxWorkspace, NttNtruCmuxWorkspace,
    NttNtruExternalProductWorkspace,
};
#[cfg(feature = "ntt")]
pub(crate) use ntt::{
    NttGlweExternalProductWorkspaceRefMut, NttNtruExternalProductWorkspaceRefMut,
};

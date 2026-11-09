//! GLev-to-GGSW scheme switching.

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::FourierGlweSchemeSwitchKey;
#[cfg(feature = "ntt")]
pub use ntt::NttGlweSchemeSwitchKey;

//! GLWE secret key types organized by domain representation.

mod coeff;
#[cfg(feature = "fourier")]
pub(crate) mod exact;
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::GlweSecretKey;
#[cfg(feature = "fourier")]
pub use fourier::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptor, FourierGlweEncryptorError,
    FourierGlweSecretKey,
};
#[cfg(feature = "ntt")]
pub use ntt::{NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};

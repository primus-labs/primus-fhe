//! NTRU secret key types.

mod coeff;
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::NtruSecretKey;
#[cfg(feature = "fourier")]
pub use fourier::{
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey,
};
#[cfg(feature = "ntt")]
pub use ntt::{NttNtruGadgetEncryptWorkspace, NttNtruSecretKey};

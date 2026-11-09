//! NTRU secret key types.

mod coeff;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::NtruSecretKey;
#[cfg(feature = "ntt")]
pub use ntt::{NttNtruGadgetEncryptWorkspace, NttNtruSecretKey};

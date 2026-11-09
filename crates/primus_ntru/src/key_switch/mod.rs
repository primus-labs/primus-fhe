//! NTRU-to-NTRU gadget products and coefficient-domain conversion to independent LWE.

#[cfg(feature = "fourier")]
mod fourier;
mod lwe;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::FourierNtruKeySwitchingKey;
pub use lwe::{
    LweReturnBatchWorkspace, LweReturnEvaluator, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace,
};
#[cfg(feature = "ntt")]
pub use ntt::NttNtruKeySwitchingKey;

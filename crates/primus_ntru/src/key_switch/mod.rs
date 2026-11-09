//! NTRU-to-NTRU gadget products and coefficient-domain conversion to independent LWE.

mod lwe;
#[cfg(feature = "ntt")]
mod ntt;

pub use lwe::{
    LweReturnBatchWorkspace, LweReturnEvaluator, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace,
};
#[cfg(feature = "ntt")]
pub use ntt::NttNtruKeySwitchingKey;

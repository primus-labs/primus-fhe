//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

mod block;
mod cbs;
mod domains;
mod keygen;
mod oracle;
mod parameters;
mod pbs;

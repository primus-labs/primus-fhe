//! Small deterministic consumers of the recommended public workflow.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

mod block;
mod cbs;
mod fixture;
mod keygen;
mod one_hot;
mod pbs;
mod split;

//! Small deterministic consumers of the recommended public workflow.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

#[path = "workflows/block.rs"]
mod block;
#[path = "workflows/cbs.rs"]
mod cbs;
#[path = "workflows/fixture.rs"]
mod fixture;
#[path = "workflows/keygen.rs"]
mod keygen;
#[path = "workflows/one_hot.rs"]
mod one_hot;
#[path = "workflows/pbs.rs"]
mod pbs;
#[path = "workflows/split.rs"]
mod split;

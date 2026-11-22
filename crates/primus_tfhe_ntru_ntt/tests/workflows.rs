//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.

#[path = "workflows/block.rs"]
mod block;
#[path = "workflows/cbs.rs"]
mod cbs;
#[path = "workflows/fixture.rs"]
mod fixture;
#[path = "workflows/keygen.rs"]
mod keygen;
#[path = "workflows/pbs.rs"]
mod pbs;

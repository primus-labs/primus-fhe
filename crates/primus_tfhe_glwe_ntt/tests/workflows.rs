//! Small deterministic consumers of the recommended public workflow.
//! n=8/N=128 are arithmetic regression parameters, not security profiles.

#[path = "workflows/block.rs"]
mod block;
#[path = "workflows/cbs.rs"]
mod cbs;
#[path = "workflows/domains.rs"]
mod domains;
#[path = "workflows/keygen.rs"]
mod keygen;
#[path = "workflows/parameters.rs"]
mod parameters;
#[path = "workflows/pbs.rs"]
mod pbs;

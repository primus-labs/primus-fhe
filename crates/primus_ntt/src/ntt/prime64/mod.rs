//! Specialized NTT for moduli below `2^62` with u64 lazy residues.
//!
//! Scalar-32, scalar-64, and AVX2 share Primus' radix-2 schedule. The AVX-512
//! backend is kept as a separately documented Intel HEXL translation because
//! its recursive schedule and forward-root layout are materially different.

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
mod precompute;
mod scalar;
mod table;

pub use table::U64NttTable;

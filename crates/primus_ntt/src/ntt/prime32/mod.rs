//! Specialized NTT for moduli below `2^30` with u32 lazy residues.
//!
//! Scalar code owns the arithmetic contract. On x86-64 the table selects AVX2
//! or AVX-512 once at construction and builds only that backend's packed root
//! layout.

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
mod scalar;
mod table;

pub use table::U32NttTable;

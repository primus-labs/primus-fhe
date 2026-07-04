#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
mod scalar;
mod table;

pub use table::U32NttTable;

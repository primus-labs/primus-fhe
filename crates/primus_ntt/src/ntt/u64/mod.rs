#[cfg(target_arch = "x86_64")]
mod avx2;
mod scalar;
mod table;

pub use table::U64NttTable;

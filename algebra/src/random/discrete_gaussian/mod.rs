mod cdt;
mod ziggurat;

pub use cdt::CDTSampler;
pub use ziggurat::DiscreteZiggurat;

#[cfg(target_os = "linux")]
mod unix_cdt;

#[cfg(target_os = "linux")]
pub use unix_cdt::UnixCDTSampler;

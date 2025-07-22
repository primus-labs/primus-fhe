mod cdt;

pub use cdt::CDTSampler;

#[cfg(target_os = "linux")]
mod unix_cdt;

#[cfg(target_os = "linux")]
pub use unix_cdt::UnixCDTSampler;

mod ziggurat;

pub use ziggurat::DiscreteZiggurat;

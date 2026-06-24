use std::fmt::Debug;

use primus_integer::Integer;
use thiserror::Error;

/// Error type for the [`primus_distr`](crate) crate.
#[derive(Error, Debug)]
pub enum DistrErr<T: Integer> {
    /// The requested standard deviation is outside the supported range.
    #[error("invalid standard deviation: {std_dev}\nmodulus minus one: {modulus_minus_one}")]
    InvalidStdDev {
        /// The requested standard deviation.
        std_dev: f64,
        /// The modulus minus one, used as a bound for sample values.
        modulus_minus_one: T,
    },
}

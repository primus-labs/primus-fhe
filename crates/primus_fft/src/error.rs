use thiserror::Error;

/// Errors that may occur during FFT table construction or operations.
#[derive(Error, Debug)]
pub enum FftError {
    /// The requested `log_n` is too large.
    ///
    /// `1usize << log_n` must be valid, so `log_n` must be less than
    /// `usize::BITS`.
    #[error("log_n {log_n} is too large; must be less than {max}")]
    InvalidLogN {
        /// The requested log2(N).
        log_n: u32,
        /// The maximum allowed value.
        max: u32,
    },
}

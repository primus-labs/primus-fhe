#[cfg(feature = "rustfft")]
mod rustfft_backend;
#[cfg(feature = "tfhe-fft")]
mod tfhe_fft_backend;

#[cfg(feature = "rustfft")]
pub use rustfft_backend::{RustFftTable, RustFftWorkspace};
#[cfg(feature = "tfhe-fft")]
pub use tfhe_fft_backend::{TfheFftTable, TfheFftWorkspace};

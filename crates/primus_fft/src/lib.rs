#![deny(missing_docs)]
//! Torus negacyclic FFT transforms for `Z[X] / (X^N + 1)`.
//!
//! Provides the [`FftTable`] trait and the [`FullComplex64FftTable`] reference
//! backend backed by the `rustfft` crate. The forward transform centers torus
//! coefficients, applies a negacyclic twist, and performs a standard complex
//! FFT. The inverse applies an IFFT, untwists, and rounds back to the torus
//! representation.
//!
//! # Backends
//!
//! - [`FullComplex64FftTable`]: stores the full `N` complex values
//!   (`fourier_length == poly_length`). Simple and correct — suitable as a
//!   reference and for testing.
//! - A future `PackedComplex64FftTable` will exploit real-input conjugate
//!   symmetry to store only `N / 2` complex values, matching the storage
//!   convention of production TFHE implementations.

/// Interleaved `Complex64` FFT backend.
pub mod complex64;
mod error;
mod table;
mod torus;

pub use complex64::FullComplex64FftTable;
pub use error::FftError;
pub use table::FftTable;
pub use torus::TorusFftValue;

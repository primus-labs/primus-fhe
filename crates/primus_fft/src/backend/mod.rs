use std::f64::consts::PI;

use aligned_vec::{ABox, AVec, CACHELINE_ALIGN};
use primus_shape::PolyLength;

use crate::Complex64;

#[cfg(feature = "rustfft")]
mod rustfft_backend;
#[cfg(feature = "tfhe-fft")]
mod tfhe_fft_backend;

#[cfg(feature = "rustfft")]
pub use rustfft_backend::{RustFftTable, RustFftWorkspace};
#[cfg(feature = "tfhe-fft")]
pub use tfhe_fft_backend::{TfheFftTable, TfheFftWorkspace};

// Both plans use the same negacyclic packing. Their unnormalized inverse
// transforms absorb the factor 1/(N/2) into the inverse twist.
fn negacyclic_twists(poly_length: PolyLength) -> (ABox<[Complex64]>, ABox<[Complex64]>) {
    let n = poly_length.get();
    let h = poly_length.fourier_poly_len();
    let twist = AVec::from_iter(
        CACHELINE_ALIGN,
        (0..h).map(|j| Complex64::cis(PI * j as f64 / n as f64)),
    )
    .into_boxed_slice();
    let inverse_twist_scaled = AVec::from_iter(
        CACHELINE_ALIGN,
        (0..h).map(|j| Complex64::cis(-PI * j as f64 / n as f64) / h as f64),
    )
    .into_boxed_slice();
    (twist, inverse_twist_scaled)
}

mod coeff;
mod extract;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "rns")]
mod crt;
#[cfg(feature = "rns")]
mod dcrt;
/// Fourier-domain GLWE ciphertexts.
#[cfg(feature = "fourier")]
mod fourier;

pub use coeff::{Glwe, GlweIter, GlweIterMut};
#[cfg(feature = "ntt")]
pub use ntt::{NttGlwe, NttGlweIter, NttGlweIterMut};

#[cfg(feature = "rns")]
pub use crt::{CrtGlwe, CrtGlweIter, CrtGlweIterMut};
#[cfg(feature = "rns")]
pub use dcrt::{DcrtGlwe, DcrtGlweIter, DcrtGlweIterMut};
#[cfg(feature = "fourier")]
pub use fourier::{FourierGlwe, FourierGlweIter, FourierGlweIterMut, FourierGlweOwned};

/// TFHE torus GLWE ciphertext (coefficient domain).
///
/// Layout: `|--a1--| ... |--ak--|--b--|` where each `a_i` and `b` is a
/// polynomial with `N` coefficients (degree less than `N`).
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusGlwe<S> = Glwe<S>;

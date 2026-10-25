mod coeff;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "rns")]
mod crt;
#[cfg(feature = "rns")]
mod dcrt;
/// Fourier-domain GGSW ciphertexts.
#[cfg(feature = "fourier")]
mod fourier;

pub use coeff::{Ggsw, GgswIter, GgswIterMut};
#[cfg(feature = "ntt")]
pub use ntt::{NttGgsw, NttGgswIter, NttGgswIterMut};

#[cfg(feature = "rns")]
pub use crt::{CrtGgsw, CrtGgswIter, CrtGgswIterMut};
#[cfg(feature = "rns")]
pub use dcrt::{DcrtGgsw, DcrtGgswIter, DcrtGgswIterMut};
#[cfg(feature = "fourier")]
pub use fourier::{FourierGgsw, FourierGgswIter, FourierGgswIterMut, FourierGgswOwned};

/// TFHE torus GGSW ciphertext (coefficient domain).
///
/// Matrix of [`TorusGlev`](crate::glev::TorusGlev) ciphertexts, one per row
/// (i.e. one per GLWE mask component plus one for the body).
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusGgsw<S> = Ggsw<S>;

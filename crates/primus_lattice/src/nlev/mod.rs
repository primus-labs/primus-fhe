mod coeff;
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::{Nlev, NlevIter, NlevIterMut};
#[cfg(feature = "fourier")]
pub use fourier::{FourierNlev, FourierNlevIter, FourierNlevIterMut, FourierNlevOwned};
#[cfg(feature = "ntt")]
pub use ntt::{NttNlev, NttNlevIter, NttNlevIterMut};

/// TFHE torus NLev ciphertext in the coefficient domain.
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusNlev<S> = Nlev<S>;

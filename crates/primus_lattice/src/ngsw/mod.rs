mod coeff;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::{Ngsw, NgswIter, NgswIterMut};
#[cfg(feature = "ntt")]
pub use ntt::{NttNgsw, NttNgswIter, NttNgswIterMut};

/// TFHE torus NGSW ciphertext in the coefficient domain.
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusNgsw<S> = Ngsw<S>;

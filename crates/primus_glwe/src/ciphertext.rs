/// Coefficient-domain GLWE ciphertext.
pub type GlweCiphertext<T> = primus_lattice::glwe::Glwe<T>;

/// NTT-domain GLWE ciphertext.
#[cfg(feature = "ntt")]
pub type NttGlweCiphertext<T> = primus_lattice::glwe::NttGlwe<T>;

/// Fourier-domain GLWE ciphertext.
#[cfg(feature = "fourier")]
pub type FourierGlweCiphertext<S> = primus_lattice::glwe::FourierGlwe<S>;

/// Coefficient-domain GLev ciphertext.
pub type GlevCiphertext<S> = primus_lattice::glev::Glev<S>;

/// NTT-domain GLev ciphertext.
#[cfg(feature = "ntt")]
pub type NttGlevCiphertext<S> = primus_lattice::glev::NttGlev<S>;

/// Fourier-domain GLev ciphertext.
#[cfg(feature = "fourier")]
pub type FourierGlevCiphertext<S> = primus_lattice::glev::FourierGlev<S>;

/// NTT-domain GGSW ciphertext.
#[cfg(feature = "ntt")]
pub type NttGgswCiphertext<S> = primus_lattice::ggsw::NttGgsw<S>;

/// Fourier-domain GGSW ciphertext.
#[cfg(feature = "fourier")]
pub type FourierGgswCiphertext<S> = primus_lattice::ggsw::FourierGgsw<S>;

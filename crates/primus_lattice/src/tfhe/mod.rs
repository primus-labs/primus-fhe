//! TFHE semantic type aliases.
//!
//! These reuse existing coefficient ciphertext containers and serve as
//! documentation of torus semantics — no new storage is created.

/// TFHE torus LWE ciphertext (coefficient domain).
///
/// Layout: `[a_1, ..., a_k, b]` — `k` mask elements + 1 body element.
pub type TorusLwe<S> = crate::lwe::Lwe<S>;

/// TFHE torus GLWE ciphertext (coefficient domain).
///
/// Layout: `|--a1--| ... |--ak--|--b--|` where each `a_i` and `b` is a
/// polynomial of degree `N-1`.
pub type TorusGlwe<S> = crate::glwe::Glwe<S>;

/// TFHE torus GLev ciphertext (coefficient domain).
///
/// List of [`TorusGlwe`] per gadget decomposition level.
pub type TorusGlev<S> = crate::glev::Glev<S>;

/// TFHE torus GGSW ciphertext (coefficient domain).
///
/// Matrix of [`TorusGlev`] ciphertexts, one per row (i.e. one per GLWE mask
/// component plus one for the body).
pub type TorusGgsw<S> = crate::ggsw::Ggsw<S>;

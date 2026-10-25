//! NTRU errors.

/// An error produced while constructing an NTRU transform-domain secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NtruError {
    /// The coefficient key, or every candidate of a fixed-weight distribution,
    /// is not invertible in the selected ring.
    #[error("NTRU secret key is not invertible in the selected ring")]
    NonInvertibleSecretKey,
    /// The Fourier representation is too ill-conditioned for stable inversion.
    #[error("NTRU secret key has an unstable Fourier inverse")]
    UnstableFourierInverse,
    /// Rejection sampling did not find a usable key within the configured limit.
    #[error("NTRU secret-key generation exhausted its rejection-sampling limit")]
    KeyGenerationExhausted,
}

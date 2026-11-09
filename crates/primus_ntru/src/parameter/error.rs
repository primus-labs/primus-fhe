//! Parameter construction errors, retaining their numerical sources.

use primus_decompose::ApproxSignedBasisError;

/// Invalid NTRU encoding or sampling parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum NtruParameterError {
    /// Invalid message/ciphertext domain or fixed-scale recovery bound.
    #[error(transparent)]
    Encoding(#[from] primus_encoding::CodecError),
    /// The ordinary message codec belongs to another ciphertext modulus.
    #[error("NTRU plaintext codec must match the encryption ciphertext modulus")]
    CodecModulusMismatch,
    /// Invalid secret sampling configuration, weight or output modulus.
    #[error(transparent)]
    SecretKey(#[from] primus_distr::SecretKeySamplerError),
    /// Invalid coefficient-domain Gaussian noise.
    #[error("invalid NTRU noise distribution")]
    Noise(#[from] primus_distr::GaussianError),
}

/// Invalid NLev/NGSW basis or ciphertext layout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NlevParameterError {
    /// The decomposition basis could not be constructed.
    #[error(transparent)]
    InvalidBasis(#[from] ApproxSignedBasisError),
    /// The supplied basis belongs to another explicit or native modulus.
    #[error("NLev basis must match the NTRU ciphertext modulus")]
    BasisModulusMismatch,
    /// N times the level count cannot be represented by usize.
    #[error("NLev ciphertext length overflow")]
    CiphertextLengthOverflow,
}

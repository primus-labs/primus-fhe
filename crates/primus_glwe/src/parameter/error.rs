//! Parameter construction errors, retaining the numerical cause.

use primus_decompose::ApproxSignedBasisError;
use primus_distr::{GaussianError, SecretKeySamplerError};
use primus_encoding::CodecError;
use primus_lattice::GlweSizeError;

/// Invalid GLWE layout, encoding or sampling parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GlweParameterError {
    /// Invalid ring dimensions or a flattened-length overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// Invalid message/ciphertext domain or fixed-scale recovery bound.
    #[error(transparent)]
    Encoding(#[from] CodecError),
    /// The ordinary message codec belongs to another ciphertext modulus.
    #[error("GLWE plaintext codec must match the encryption ciphertext modulus")]
    CodecModulusMismatch,
    /// Invalid secret sampling configuration, weight or output modulus.
    #[error(transparent)]
    SecretKey(#[from] SecretKeySamplerError),
    /// Invalid coefficient-domain Gaussian noise.
    #[error("invalid GLWE noise distribution")]
    Noise(#[from] GaussianError),
}

/// Invalid GLev/GGSW encryption state, decomposition, secret weight or layout.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GlevParameterError {
    /// The ciphertext-domain sampling state could not be prepared.
    #[error("invalid GLev/GGSW encryption parameters")]
    Encryption(#[from] GlweParameterError),
    /// The decomposition basis could not be constructed.
    #[error(transparent)]
    InvalidBasis(#[from] ApproxSignedBasisError),
    /// The basis and GLWE ciphertext use different moduli.
    #[error("GLev decomposition basis must match the GLWE ciphertext modulus")]
    BasisModulusMismatch,
    /// The gadget layout cannot be represented by `usize` lengths.
    #[error(transparent)]
    InvalidSize(#[from] GlweSizeError),
    /// The prepared secret sampler's fixed weight does not fit the GLWE layout.
    #[error(transparent)]
    SecretKey(#[from] SecretKeySamplerError),
}

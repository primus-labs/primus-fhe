//! Plaintext encoding and decoding for homomorphic encryption.
//!
//! [`RoundedCodec`] rounds each scaled message; [`ScaledCodec`] uses a fixed
//! rounded integer scale. Both support native and explicit ciphertext moduli.
//! The optional `rns` feature provides BFV coefficient scaling and decoding over
//! an RNS ciphertext basis. [`MessageDecoder`] reuses either single-modulus
//! codec's prepared q-to-t decoding. Public types are available at the crate root.
//! These codecs do not implement integer slot packing or CKKS canonical embedding.
//! [`phase_error_magnitude`] measures an extracted phase against an explicitly
//! expected encoded phase, independently of decoding or secret keys.
//!
//! The `simd` feature enables nightly SIMD arithmetic in dependencies.

#![deny(missing_docs)]

mod decode;
mod helpers;
mod integer_scale;
mod phase_error;
mod rounded;
mod scaled;

pub use decode::MessageDecoder;
pub use phase_error::{phase_error_magnitude, phase_error_magnitude_slice_to};
pub use rounded::RoundedCodec;
pub use scaled::ScaledCodec;

/// Invalid plaintext/ciphertext domain or fixed-scale recovery bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// A plaintext domain needs at least two residues.
    #[error("plaintext modulus must be at least two")]
    InvalidPlaintextModulus,
    /// The ciphertext modulus must be larger than the plaintext modulus.
    #[error("ciphertext modulus must exceed plaintext modulus")]
    CiphertextModulusTooSmall,
    /// Fixed rounded scaling cannot guarantee noiseless recovery for both lifts.
    #[error("ciphertext modulus too small for fixed rounded scaling")]
    InsufficientScaleRecovery,
}

#[cfg(feature = "rns")]
mod bfv_rns;
#[cfg(feature = "rns")]
pub use bfv_rns::{BfvRnsCodec, BfvRnsCodecError};

/// Plaintext embedding used when lifting residues from `Z_t` into the ciphertext modulus.
/// Both variants accept messages as canonical residues in `[0,t)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextEmbedding {
    /// Lifts messages as unsigned residues in `[0, t)`.
    Unsigned,
    /// Uses `m` below `ceil(t/2)` and `m-t` otherwise, giving the centered
    /// interval `[-floor(t/2), ceil(t/2))`. For `t = 2`, residue `1` lifts to `-1`.
    Centered,
}

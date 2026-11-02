use primus_decompose::ApproxSignedBasisError;
use primus_integer::FheUint;
use primus_lattice::GlweSizeError;

/// Invalid codec-free RNS GLWE sampling state or its ordered domain.
#[derive(Debug, thiserror::Error)]
pub enum CrtGlweEncryptionParametersError<T: FheUint> {
    /// The supplied layout and ordered sampler basis differ.
    #[error(transparent)]
    Domain(#[from] super::RnsDomainError<T>),
    /// Invalid secret probabilities, fixed weights or supported magnitudes.
    #[error(transparent)]
    SecretKey(#[from] primus_distr::SecretKeySamplerError),
    /// Invalid integer error distribution or insufficient modulus support.
    #[error("invalid CRT GLWE error sampler")]
    ErrorSampler(#[from] primus_distr::ErrorSamplerError),
}

/// An invalid decomposition basis or layout for CRT GLev/GGSW parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrtGlevParametersError<T: FheUint> {
    /// A derived gadget storage length is not representable.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
    /// The supplied ordered base does not match the prepared sampler domain.
    #[error(transparent)]
    Domain(#[from] super::RnsDomainError<T>),
    /// The decomposition basis has a different product modulus or limb width.
    #[error("CRT GLev decomposition must match the RNS product modulus and limb width")]
    BasisModulusMismatch,
    /// The decomposition parameters are invalid for the product modulus.
    #[error(transparent)]
    InvalidDecomposition(#[from] ApproxSignedBasisError),
    /// The fast centered lift requires the basis to be smaller than every modulus.
    #[error(
        "decomposition basis {basis:?} must be smaller than RNS modulus {modulus:?} at index {index}"
    )]
    BasisNotSmallerThanModulus {
        /// Decomposition radix.
        basis: T,
        /// RNS modulus that violates the centered-lift precondition.
        modulus: T,
        /// Index in the ordered RNS base.
        index: usize,
    },
}
